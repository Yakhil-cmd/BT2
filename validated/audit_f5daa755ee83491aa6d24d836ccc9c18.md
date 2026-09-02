Confirmed. `StatusHandler` proves the strongest reachable analog.

### Title
Webhook signature verifies the claimed organization but commit-status/CI writes are scoped only by an attacker-controlled `repository.full_name`, allowing cross-tenant CI status forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
In multi-organization Shipit deployments (`Using Multiple Github Applications`), `WebhooksController#verify_signature` selects which `webhook_secret` to validate a request against using an organization name pulled straight out of the *unverified* JSON body, before the signature is checked [1](#0-0) . Once that org's secret validates the request, the event is dispatched to handlers that resolve the actual write target from a *different* field of the same attacker-controlled body (`repository.full_name`) with no re-check that it belongs to the organization whose secret was used [2](#0-1) . This breaks the intended binding "organization that authenticated == repository that is written."

### Finding Description
`Shipit.github(organization: repository_owner)` is looked up using `repository_owner`, which is read from `params.dig('repository','owner','login')` (or `organization.login`) of the raw, not-yet-verified body [3](#0-2) . In a multi-org install, each org has its own `webhook_secret`, as shown by the documented config schema and dummy fixtures with `OrgOne`/`OrgTwo` [4](#0-3) [5](#0-4) . The owner of a legitimate low-trust org (e.g. `OrgA`) knows *their own* app's `webhook_secret` because they configured it themselves when creating their GitHub App, per the setup docs ("keep it in clear on the side, you'll need it later") [6](#0-5) .

That org owner can POST an arbitrary JSON body directly to `/webhooks` with `repository.owner.login = "OrgA"` (so `verify_signature` picks OrgA's app and validates the HMAC they computed with their own known secret) while setting `repository.full_name = "OrgB/victim-repo"`. `Handler#repository_name` and `Handler#stacks` then resolve the *victim* org's stacks using that unchecked `full_name` [2](#0-1) , and `StatusHandler#process` writes an attacker-fully-controlled `Commit::Status` (`state`, `target_url`, `description`, `context`, `created_at`) onto any commit whose `sha` matches, cross-referenced only by `Commit.where(sha: params.sha)` with no organization/stack scoping at all [7](#0-6) . `PushHandler` has the same repository-binding gap and can force an unrelated stack to `sync_github`, which schedules `GithubSyncJob` for that stack id [8](#0-7) [9](#0-8) .

Before the attacker's request: the signature check and the resource-selection field are logically the same organization/repository for legitimate GitHub-originated payloads, since GitHub itself fills in a consistent `repository` object. After the attacker's crafted request: the signature-selected org (`OrgA`, whose secret the attacker legitimately possesses) and the write-target repository (`OrgB/victim-repo`, taken from the same JSON body) diverge, because nothing re-validates that `repository.full_name`'s owner matches `repository_owner`/the app used for verification.

### Impact Explanation
A forged `success` status on a required CI context for a victim commit can satisfy `StatusChecker`/merge-queue and deploy required-checks logic (`required_statuses`, `blocking_statuses` in `DeploySpec`) for a stack the attacker has no access to, enabling an unauthorized merge or deploy of a commit that never actually passed CI in that other tenant's repository. This matches the Critical/High impact bar ("unauthorized deploy, rollback or merge") because it lets a party who only administers their own, unrelated GitHub org organization's webhook secret manipulate build/CI state and trigger sync/deploy machinery for a repository they do not own.

### Likelihood Explanation
This requires a Shipit deployment configured with multiple GitHub organizations (the documented "Using Multiple GitHub Applications" mode), and requires the attacker to be the legitimate administrator of one of those organizations' GitHub Apps (so they know that org's own `webhook_secret`) but not of the victim org. This is plausible in any Shipit instance shared across multiple, mutually-untrusting teams/orgs — exactly the scenario the multi-org feature exists for — and requires no `ApiClient` token, no `github_access_token`, and no privileged Shipit account; it only requires crafting a raw HTTP POST with a valid HMAC for one's own org.

### Recommendation
Bind the resource-lookup fields to the same trust anchor used for signature verification: after `verify_signature` resolves `repository_owner`/organization from the payload, re-derive `repository_owner` from `repository.full_name` (or vice versa) and reject the request (422) if they don't match. Alternatively, pass the verified organization into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, organization: repository_owner) }` and have `Handler#stacks`/`repository_name` filter/verify against that organization instead of trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org schema).
2. As the administrator of `OrgA` (who knows `OrgA`'s `webhook_secret`), craft:
```json
{
  "sha": "<victim-commit-sha-in-OrgB-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` selects `Shipit.github(organization: "OrgA")` and successfully verifies the signature [10](#0-9) .
5. `StatusHandler#process` matches the commit by `sha` in `OrgB/victim-repo` (no org check) and writes the forged `success` status [11](#0-10) , which the test suite confirms directly creates/updates a `Status` from webhook fields [12](#0-11) .

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
