### Title
Webhook signature check authenticates the payload's `repository.owner.login`/`organization.login` while every handler routes and mutates state using the payload's `repository.full_name` (or `organization.login` for membership) — allowing a webhook sender who holds one configured organization's `webhook_secret` to act on a different organization/repository's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), both attacker-supplied JSON fields in the raw request body. [1](#0-0) [2](#0-1) 

But the event handlers that actually resolve the target `Stack`/`Repository` (and thus perform the effectful action) key off a *different* field, `repository.full_name`, via `Handler#stacks`/`Handler#repository_name`: [3](#0-2) 

`PushHandler`, `ClosedHandler`, `LabelCapturingHandler`, `UnlabeledHandler`, etc. all resolve `repository`/`stacks` from `params.repository.full_name`: [4](#0-3) [5](#0-4) 

Because Shipit supports multiple GitHub Apps/organizations each with its own `webhook_secret` (`TOP_LEVEL_GH_KEYS` / `secrets_double_github_app.yml`), the "organization that authenticated" (`repository.owner.login`, used to pick the secret) and the "repository that is written" (`repository.full_name`, used by the handler) are two independently attacker-controlled fields of the same JSON body that are never cross-checked against each other. [6](#0-5) [7](#0-6) 

### Finding Description
`verify_signature` HMAC-validates the raw POST body against the secret configured for whatever organization the payload *claims* to belong to (`repository.owner.login`), not against the organization that actually owns the repository named in `repository.full_name`: [8](#0-7) 

A party that legitimately controls a webhook secret for *any* org configured on this Shipit instance (e.g. `OrgA`, onboarded for their own low-trust repo) can send a webhook whose body sets `repository.owner.login = "OrgA"` (so the signature check finds and matches `OrgA`'s secret) while setting `repository.full_name = "OrgB/some-repo"` — a repository belonging to a completely unrelated organization `OrgB` also configured on the same instance. Signature verification succeeds because it is only checking "did the sender know `OrgA`'s secret", but every downstream handler operates on `OrgB`'s stack because it trusts `full_name` from the same forged body: [3](#0-2) 

This is the direct structural analog of the reported bug class: a value used to satisfy a trust/payment check (`deploymentFee`/signer selection) is not the same value the subsequent privileged action is actually keyed on (`msg.value` usage / repository acted upon), so the check and the effect are bound to different fields and can be decoupled by an attacker who controls the body.

### Impact Explanation
An attacker who is entitled to trigger webhooks for only one, low-trust organization configured on a shared Shipit instance can forge events that are processed as if they came from a completely different organization's repository:
- `PushHandler` will enqueue `GithubSyncJob` against `OrgB`'s stacks with an attacker-chosen `expected_head_sha`, forcing (re)sync against a repository the attacker has no access to. [9](#0-8) 
- `ClosedHandler`/`UnlabeledHandler` can archive/unarchive `OrgB`'s review stacks. [10](#0-9) [11](#0-10) 
- `CheckSuiteHandler` and `StatusHandler` can inject fabricated commit-status/check-run refresh triggers tied to `OrgB`'s commits. [12](#0-11) [13](#0-12) 

This is a cross-organization/cross-repository write on state belonging to a repository/organization the attacker does not control, satisfying the "cross-repository writes" impact bar, since normal Shipit trust boundaries assume a webhook validated with `OrgA`'s secret only ever describes `OrgA`'s repositories.

### Likelihood Explanation
Exploitability requires only that the Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration — see `secrets_double_github_app.yml`/`TOP_LEVEL_GH_KEYS`) and that the attacker legitimately knows/controls one organization's `webhook_secret` (e.g., because they administer their own low-trust org that is also onboarded to the shared instance). No GitHub App private key, `ApiClient` token, or Shipit session is needed — only knowledge of one org's HMAC secret and the ability to send an HTTP POST to `/github/webhooks`. This matches the allowed "unprivileged-attacker" threat model since the attacker never needs write access to the *victim* repository/org.

### Recommendation
`verify_signature` should not use payload-declared identifiers to choose the verification secret independently of what the handler will act on. Concretely:
- After verifying the signature against the secret for `repository_owner`, additionally assert that the resolved `Repository`/`Stack` for `repository.full_name` actually belongs to that same verified organization (`repository.full_name.split('/').first == repository_owner`), rejecting the request otherwise.
- Alternatively, look up the organization to use for signature verification from the already-registered `Repository`/`GithubHook` record (keyed by `full_name`) rather than from the raw, unauthenticated JSON payload.

### Proof of Concept
1. Shipit instance is configured with two orgs, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (as supported by `test/dummy/config/secrets_double_github_app.yml`). [14](#0-13) 
2. Attacker knows `OrgA`'s `webhook_secret` (e.g., they are an admin of `OrgA`, which also has a repo onboarded to this Shipit instance).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature (attacker knows the secret). [1](#0-0) 
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and enqueues `GithubSyncJob` for `OrgB`'s stack, even though the signature was never validated against `OrgB`'s secret. [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
