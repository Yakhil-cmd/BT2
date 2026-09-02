Based on my research, I found a concrete analog to this bug class in the shipit-engine's webhook handling. Given the limited remaining iterations, I'll present my finding now.

### Title
Webhook signature verification is keyed on an attacker-controlled organization field that is never cross-checked against the repository the event actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The M-11 report describes a trust-binding break where the field used to authorize an action (the "unpaused" state) is disconnected from the field an attacker can independently manipulate (the race/front-run on liquidation). The shipit-engine analog is that `WebhooksController#verify_signature` selects *which* GitHub App/webhook secret to authenticate against using one payload field (`repository.owner.login` / `organization.login`), while every `Shipit::Webhooks::Handlers::Handler` subclass resolves the repository to act on (and thus write to) using a completely different, unauthenticated payload field (`repository.full_name`). These two fields are never cross-validated against each other.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to verify against based on the attacker-supplied `repository_owner`: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` treats an organization with **no configured `webhook_secret`** as fully trusted, bypassing signature checking entirely: [3](#0-2) 

Meanwhile, every handler dispatched from `create` resolves the actual repository/stacks to mutate using a **different, unauthenticated** field — `repository.full_name` — with no comparison back to `repository_owner`/`organization.login` that was used for signature selection: [4](#0-3) 

This is the equality the deployment-trust model assumes but never enforces: `organization authenticated in verify_signature == owner(full_name acted upon by handlers)`. Because GitHub's real webhooks always keep these fields consistent, the engine never validates it — but an attacker submitting a raw POST directly to the webhooks endpoint controls both fields independently.

### Impact Explanation
If any GitHub organization configured in `Shipit.github_configs` has no `webhook_secret` set (a common, easy-to-make config state — e.g. an org added without ever wiring up the shared secret), `verify_webhook_signature` returns `true` unconditionally for *any* payload claiming that organization as `repository.owner.login`, regardless of what is in `X-Hub-Signature`. The attacker then sets `repository.full_name` to an arbitrary tracked victim repository/stack belonging to a *different*, properly-secured organization. Handlers such as `Handlers::StatusHandler` will create a commit status (e.g. forging a `success` CI status) on the victim stack's commit, and `Handlers::PushHandler` will trigger a resync using an attacker-chosen `after` SHA. Forged CI status can satisfy `ci.require` checks in `shipit.yml` gating deploys/continuous-deployment, enabling an unauthorized deploy of a commit on a repository the attacker has no access to and for which the correct secret was never presented.

### Likelihood Explanation
Requires a multi-tenant Shipit install where at least one onboarded GitHub organization has a blank `webhook_secret` (config omission, not a documented misuse of the engine). No GitHub session, `ApiClient` token, or repository write access is needed — the request is a raw unauthenticated POST to `/webhooks`.

### Recommendation
In `WebhooksController#verify_signature`, require every configured organization to have a non-blank `webhook_secret` (fail closed instead of `return true unless webhook_secret`), and cross-validate that `repository.owner.login`/`organization.login` used to select the signing organization actually matches the owner of `repository.full_name` used by handlers before dispatching.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (proper `webhook_secret`) and `attacker-org` (no `webhook_secret` set).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim-target-sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `verify_webhook_signature` returns `true` unconditionally since no secret is set.
4. `Handlers::StatusHandler` resolves the target using `repository.full_name = "victim-org/victim-repo"` and writes a forged success status on the victim's commit, satisfying `ci.require` for that stack. [5](#0-4) [3](#0-2) [4](#0-3)

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
