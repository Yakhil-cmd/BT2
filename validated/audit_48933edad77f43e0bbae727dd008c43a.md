Confirmed: `StatusHandler#process` in `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` matches `Commit.where(sha: params.sha)` across **all** stacks/repositories globally — it does not scope by `repository_owner`/`full_name` at all, so a forged `sha` collision would apply cross-repo too, but more importantly it directly calls `commit.create_status_from_github!(params)`, writing an arbitrary CI status without re-verifying with GitHub, and this can flip a commit to `deployable?` (satisfying `ci.require`, see `app/models/shipit/deploy_spec.rb:194-196` and `README.md:446-453`), enabling continuous-deployment auto-deploy or a manual deploy for a repository the attacker doesn't own.

### Title
Webhook organization-authentication bypasses cross-repository binding, allowing forged CI status / push events for any tracked repository — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the HMAC against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Once the signature is accepted, the very same raw body is re-parsed and dispatched to handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers) which act on a **different** field, `repository.full_name` (or `sha` for status), to decide which `Repository`/`Stack`/`Commit` to mutate. The field that authenticates the sender (repository/organization owner) is never checked against the field that is actually written to.

### Finding Description [1](#0-0) 
`verify_signature` picks the app config with `Shipit.github(organization: repository_owner)` and HMAC-verifies `request.raw_post` against that organization's `webhook_secret`. `repository_owner` is derived purely from the payload: [2](#0-1) 

`create` then re-parses the same JSON and fans it out to handlers: [3](#0-2) 

Handlers derive the actual target repository from a *different* payload field, `repository.full_name`: [4](#0-3) 

`PushHandler` uses that repository lookup to trigger a live sync of a stack: [5](#0-4) 

`StatusHandler` is worse: it doesn't even use `repository.full_name` — it matches purely by commit `sha` across the *entire* database and persists whatever `state`/`context` is supplied directly as a GitHub-origin status, with no re-verification against GitHub's API: [6](#0-5) 

Shipit natively supports multiple tenants/organizations sharing one instance, each with its own `webhook_secret`, as documented and tested: [7](#0-6) [8](#0-7) 

An attacker who legitimately owns/administers **one** of the configured organizations (and therefore legitimately knows that organization's own `webhook_secret`, e.g. because they created the GitHub App and installed it on their own org) can compute a valid HMAC for an arbitrary POST body of their choosing and send it directly to the shared `WebhooksController#create` endpoint (no need to go through GitHub, no need for GitHub to actually emit the event). Because `verify_signature` only checks the signature against the org named inside `repository.owner.login`, the attacker sets that field to their own org (so their own known secret validates), while setting `repository.full_name` (for push/PR events) or `sha` (for status events) to point at a completely different, victim-owned repository/commit tracked by the same Shipit instance. The equality the code should enforce — `verified_organization == repository_being_written` — is never checked; only `verified_organization == claimed_owner_field`, and `claimed_owner_field` and `repository_being_written` come from the same attacker-controlled JSON body and can be set independently.

### Impact Explanation
Via `StatusHandler`, the attacker can forge a `success` commit status for any commit hash in any tracked repository, which is used by `Commit#deployable?`/`required_statuses` to gate `ci.require` checks (`app/models/shipit/deploy_spec.rb:194-196`, `README.md:446-453`). If the victim stack has `continuous_deployment` enabled, or a legitimate user then triggers a manual deploy, this forged status can unlock an otherwise CI-blocked deploy — an unauthorized deploy driven entirely by a cross-tenant credential the attacker legitimately controls only for their own, unrelated organization. Via `PushHandler`, the attacker can also force arbitrary `GithubSyncJob` runs against the victim's stack. This satisfies the High/Critical impact bar ("unauthorized deploy") using a credential-authentication vs. repository-written binding break explicitly called out as in-scope.

### Likelihood Explanation
Requires the Shipit deployment to be configured for more than one GitHub organization (a documented, supported configuration, not a misuse) and for the attacker to control at least one of those tenant organizations' Apps — i.e., an unprivileged attacker relative to the victim organization, but a legitimate low-privilege tenant of the shared instance. No access to the victim's webhook secret, GitHub token, or session is required.

### Recommendation
After parsing the payload, verify that the organization/owner used to select the verification key (`repository.owner.login` / `organization.login`) matches the owner of the repository actually referenced for the write path (`repository.full_name`, or for status events, resolve via the commit's stack's repository owner) before dispatching to handlers. Reject the webhook if these do not match.

### Proof of Concept
1. Configure Shipit with two tenants, `attacker-org` and `victim-org`, each with its own `webhook_secret` (as supported per `docs/setup.md`).
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that GitHub App).
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/irrelevant-repo"}
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker_org_webhook_secret, body)` and POSTs to the shared `/webhooks` endpoint with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "attacker-org")`, verifies successfully with the attacker's own secret.
6. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches `Commit.where(sha: params.sha)` — which resolves to the victim's commit in `victim-org`'s stack — and calls `create_status_from_github!`, marking it `success`, potentially satisfying `ci.require` and unblocking a deploy for `victim-org`'s stack that the attacker has no authorization over.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
      end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
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
```
