### Title
Webhook signature verification binds only to the payload's `repository.owner.login`, not to `repository.full_name` acted upon by handlers, allowing cross-organization commit-status/stack forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GithubApp` (and thus the webhook secret) to verify a webhook's HMAC signature using `params.dig('repository', 'owner', 'login')` (or `organization.login`). But every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and all `PullRequest::*` handlers) resolves the target `Repository`/`Stack` using a completely different field: `payload.dig('repository', 'full_name')`. No code anywhere checks that these two fields are consistent for the same payload.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and asks `Shipit.github(organization: repository_owner)` for that organization's configured `webhook_secret`, then verifies the raw POST body's HMAC against it: [1](#0-0) 

This only proves "whoever sent this HTTP request knows the webhook secret configured for the organization named in `repository.owner.login`." It says nothing about which repository the rest of the JSON payload claims to be about.

Every handler, however, derives the repository/stack to act on from a **different** JSON field, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`, and downstream via `Repository.from_github_repo_name`: [2](#0-1) [3](#0-2) 

`PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all key off `sha`/`full_name`/`branch` without ever consulting `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

The engine explicitly supports multiple GitHub organizations/apps configured with independent webhook secrets on a single Shipit instance, as shown in the multi-org secrets fixture: [7](#0-6) 

The equality that should be enforced but isn't:
`organization_whose_secret_signed_the_request == owner(repository.full_name acted upon by the handler)`

Before the flaw: for a genuine GitHub webhook, `repository.owner.login` and the owner segment of `repository.full_name` are always identical, so this equality happens to hold naturally and nobody noticed it isn't actually checked.

After an attacker's request: an attacker who legitimately controls their own GitHub organization ("OrgA") on the same multi-tenant Shipit instance (and therefore legitimately knows OrgA's webhook secret, since GitHub App owners configure/see their own webhook secret) can send a raw POST directly to `/webhooks` with:
- `repository.owner.login` = `"OrgA"` (so `Shipit.github(organization: "OrgA")` is used for verification, and the attacker signs the raw body correctly with OrgA's real secret — signature check passes)
- `repository.full_name` = `"VictimOrg/victim-repo"` (a different tenant's repository)

`verify_signature` passes because the signature really was produced with OrgA's secret over this exact body. The handler then acts on `VictimOrg/victim-repo` because that's the only field it looks at. Notably, the codebase's own test fixture already demonstrates this exact `owner.login` vs `repository.full_name` mismatch existing untested/unenforced in a payload: [8](#0-7) 

### Impact Explanation
The most severe reachable primitive is `StatusHandler`, which writes a GitHub commit status directly onto any `Commit` row in the database matching the forged `sha`, with no ownership check at all — it looks the commit up globally by `sha`: [5](#0-4) 

A forged `state: "success"` status is persisted via `create_status_from_github!` → `add_status`, which recomputes `Commit#status`/`deployable?` and can trigger `stack.schedule_merges` and continuous delivery: [9](#0-8) [10](#0-9) 

Since `deployable?` gates on CI status (`success? && !blocked?`) and `ci.require`/CI-status logic solely trusts data stored in the `statuses` table, an attacker who only controls their own tenant's webhook secret can inject a fabricated "all checks passed" status for a victim tenant's commit, satisfying deploy-gating checks that were never actually run by the victim's CI, leading to an **unauthorized deploy** of a commit that never actually passed CI. `PushHandler`/`CheckSuiteHandler` allow similar unauthorized resyncs/check-run refresh triggers scoped to a victim's stack.

This crosses the "unauthorized deploy" impact bucket defined in scope, via a cross-tenant write that was supposed to be blocked by signature verification but isn't, because verification checks the wrong field.

### Likelihood Explanation
Requires only that the attacker operates their own organization/GitHub App tenant on the same multi-tenant Shipit deployment (a configuration the engine explicitly documents and tests support for — no Shipit account, ApiClient token, or repository write access to the victim's repo is needed) and can send a raw HTTP POST to the public `/webhooks` endpoint with a crafted JSON body and a correctly-computed HMAC using their own known secret.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, enforce that the organization used to select the webhook secret is the same organization that owns the repository the handler is about to act on — i.e., validate `repository.owner.login` (or `organization.login`) against the owner segment of `repository.full_name` before dispatching to handlers, or derive the acting repository from `repository.owner.login` + repo name consistently with what was cryptographically verified, rejecting the request (422) on mismatch.

### Proof of Concept
1. Attacker controls GitHub org `orga`, installed on the shared Shipit instance, and knows `orga`'s `webhook_secret` (configured by them in their own GitHub App settings, per `docs/setup.md`).
2. Attacker crafts payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "victimorg/victim-repo"
  }
}
```
   for a `push` event, or for a `status` event:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "repository": { "owner": { "login": "orga" }, "full_name": "victimorg/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(orga_secret, raw_body)>`.
4. POST to `/webhooks` with headers `X-Github-Event: status` (or `push`) and the signature.
5. `verify_signature` looks up `Shipit.github(organization: "orga")`, verifies successfully (it was indeed signed by `orga`'s secret).
6. `StatusHandler`/`PushHandler` resolves the target `Commit`/`Stack` via `victimorg/victim-repo`'s `full_name`, unaffected by the fact that the verified organization was `orga`, and persists a forged status or triggers a sync for the victim's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/fixtures/payloads/provision_disabled_pull_request.json (L340-352)
```json
  "repository": {
    "id": 186853002,
    "node_id": "MDEwOlJlcG9zaXRvcnkxODY4NTMwMDI=",
    "name": "shipit-engine",
    "full_name": "george/cyclimse",
    "private": false,
    "owner": {
      "login": "Codertocat",
      "id": 21031067,
      "node_id": "MDQ6VXNlcjIxMDMxMDY3",
      "avatar_url": "https://avatars1.githubusercontent.com/u/21031067?v=4",
      "gravatar_id": "",
      "url": "https://api.github.com/users/Codertocat",
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
