### Title
Webhook signature is validated against a GitHub App/secret selected from an attacker-controlled `repository.owner.login` field, while handlers act on a different, unchecked `repository.full_name` field — allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/`webhook_secret` to validate a request against by reading `repository.owner.login` (or `organization.login`) out of the still-unverified JSON body. Once the HMAC check passes, `WebhooksController#create` dispatches the same body to event handlers, which look up the target `Stack`/`Repository` using a *different* field of that body — `repository.full_name` — without ever re-checking that it belongs to the organization whose secret validated the signature. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Shipit explicitly supports hosting multiple independent GitHub organizations, each with its own App/`webhook_secret`, as documented for the "Using Multiple Github Applications" configuration. [4](#0-3) 

The webhook signature check is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`repository_owner` is read from the raw JSON body that has not yet been authenticated — it is only used to *select which secret to verify with*. The HMAC itself (`sha1=` of the whole `raw_post`) is computed by `verify_webhook_signature` in `GithubApp`: [6](#0-5) 

After the signature passes, `create` fans the same payload out to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [7](#0-6) 

Every handler resolves the target repository/stack from a **separate** field, `repository.full_name`, via `Handler#repository_name`/`#stacks`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler`, `StatusHandler`, and the `pull_request/*` handlers all use this same `repository.full_name`-based resolution (`Repository.from_github_repo_name(...)`), e.g.: [8](#0-7) [9](#0-8) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-on repository) are two independent, attacker-supplied fields of the same forged request body, an attacker who legitimately controls their own GitHub organization/App installed on the same Shipit instance (and therefore knows that org's `webhook_secret`) can craft a payload where:
- `repository.owner.login` / `organization.login` = the attacker's own org (so `Shipit.github(organization: ...)` resolves to a `GithubApp` whose secret the attacker knows), and
- `repository.full_name` = `"victim-org/victim-repo"` (a completely different, unrelated organization's repository tracked as a Shipit `Stack`).

The whole raw body — including both fields — is signed by the attacker with their own known secret, so `verify_webhook_signature` succeeds. `create` then dispatches this validly-signed-but-cross-tenant payload to handlers that operate on the victim repository's stacks, because the handlers never re-derive/re-check `repository.owner.login` against the organization that authenticated the request.

This is exactly the binding break called out by the rules: *"an organization that authenticated versus the repository that is written."* Before the attack: `authenticated_org == acted_on_repo.owner` always holds for genuine GitHub-signed payloads. After the attack: `authenticated_org (attacker's org) != acted_on_repo.owner (victim org)`, yet the request is treated as fully trusted.

### Impact Explanation
The most direct exploitation path is the `status` webhook event, handled by `Shipit::Webhooks::Handlers::StatusHandler`, which creates `Status` records for a given commit SHA scoped only by `repository.full_name`. Commit statuses gate whether CI is considered green for merging/deploying (`Shipit::Commit`, `Shipit::CommitChecks`, `Shipit::Status::Group`, `Shipit::MergeRequest`). [10](#0-9) 

By forging a `status` webhook validly signed with the attacker's own (unrelated, unprivileged) org's secret but targeting a victim organization's tracked repository/commit, the attacker can inject arbitrary CI status ("success") for a commit they do not control, defeating the "wait for green CI" gate that stacks with `continuous_deployment`/merge-queue rely on before shipping. This can enable an **unauthorized deploy** of a victim's stack — matching the Critical impact bar ("an unauthorized deploy, rollback or merge").

Other handlers (`push`, `pull_request/*`, `check_suite`, `membership`) are similarly reachable cross-tenant, allowing an attacker to trigger `GithubSyncJob`s, mutate PR/review-stack state, or create/delete team memberships for a victim org's Shipit-tracked resources without ever having credentials for that victim org.

### Likelihood Explanation
Exploitation requires only that the attacker operate their own, independent GitHub organization/App that is also configured on the same multi-tenant Shipit instance (a documented, supported, and unprivileged setup) — no access to the victim's webhook secret, GitHub credentials, or Shipit session/API token is needed. The attacker fully controls the JSON body they send (this is a raw, unauthenticated HTTP POST to `/webhooks`), so crafting divergent `repository.owner.login` and `repository.full_name` fields is trivial. This is a realistic and low-effort attack for any operator running Shipit for multiple orgs.

### Recommendation
After signature verification, re-derive the trusted organization strictly from the field that authenticated the request (`repository.owner.login`/`organization.login`) and reject/ignore the webhook if `repository.full_name`'s owner segment does not match that same organization, before dispatching to any handler. Alternatively, bind handlers to receive/require the already-authenticated organization explicitly rather than re-parsing an untrusted `repository.full_name` field independently.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md` "Using Multiple Github Applications") with two orgs: `attacker-org` (attacker is an admin, knows `webhook_secret_A`) and `victim-org` (tracked as a Shipit `Stack`, `webhook_secret_B` unknown to attacker).
2. Attacker builds a `status` event JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#repository_owner` returns `"attacker-org"` → `Shipit.github(organization: "attacker-org")` returns the attacker's own `GithubApp`, whose `verify_webhook_signature` succeeds against `webhook_secret_A`. [1](#0-0) 
5. `create` dispatches the parsed body to `StatusHandler`, which resolves the target stacks via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, and records a forged `"success"` status against the victim's commit — despite the request never being signed by `victim-org`'s secret. [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/commit.rb (L1-1)
```ruby
# frozen_string_literal: true
```
