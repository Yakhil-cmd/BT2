### Title
Webhook signature verification is bound to `repository.owner.login`, but state-changing handlers write to `repository.full_name` / bare commit `sha` with no cross-check — cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate an incoming webhook against using `repository.owner.login` from the untrusted JSON body, but the handlers that actually mutate state (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers) resolve which `Repository`/`Stack`/`Commit` to act on using a *different* body field: `repository.full_name` (or, for `StatusHandler`, no repository scoping at all, just a global `sha` lookup). These two fields are never checked for consistency, so the "organization that authenticated" and "the repository that is written" are decoupled — exactly the binding-break class illustrated by the FluidLocker report (verifying one thing, acting on another).

### Finding Description
The signature check:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

selects the per-org config, and if that org has no `webhook_secret` configured, verification is a no-op:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

Shipit explicitly supports multi-organization deployments where each org has its own independent `webhook_secret` entry in `secrets.yml`, and the shipped example configs leave `webhook_secret` blank by default: [3](#0-2) 

Meanwhile, the base `Handler` class — used by `PushHandler`, the pull-request handlers, `CheckSuiteHandler`, etc. — resolves the target `Repository`/`Stack` from a *different* JSON field, `repository.full_name`, which is never compared to `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`StatusHandler` is worse: it doesn't scope to a repository at all, it matches on a bare commit SHA across the *entire* `commits` table:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

Because `verify_signature` never binds `repository_owner` to the `repository.full_name`/`sha` values that the dispatched handler actually consumes, an attacker who can satisfy the signature check for org A (either because org A intentionally has no `webhook_secret` configured, as shown by the example configs, or because they otherwise control a valid signature for org A) can set `repository.full_name` (and/or `sha`) to point at a completely unrelated repository/stack tracked under org B on the same Shipit instance. The invariant the code should enforce — `authenticated_org == owner(repository_acted_on)` — is broken.

### Impact Explanation
This breaks a credential/repository boundary: it enables cross-repository/cross-organization forged writes without any GitHub credential for the victim org.
- Via `StatusHandler`, an attacker can inject arbitrary CI `state`/`context`/`description` onto any commit tracked by any stack in the installation just by knowing the target `sha`, using a signature valid only for an unrelated (or secret-less) org. This can flip a commit to `success`, which can enable continuous deployment and bypass CI gating (`ci.require`) used to guard deploys.
- Via `PushHandler`/`CheckSuiteHandler`, forged events can trigger `GithubSyncJob`/`RefreshCheckRunsJob` against arbitrary tracked stacks belonging to a different organization than the one whose signature was actually checked.
This matches the "cross-repository writes" / unauthorized deploy impact bucket.

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (it's meant to be called by GitHub) and reachable by anyone who can produce a valid `X-Hub-Signature` for any one configured org — including an org with no `webhook_secret` set, a state the shipped example configs treat as a normal/default value. No Shipit session, `ApiClient` token, or GitHub App private key is required; the attacker only needs to control the JSON body's `repository.owner.login`/`full_name`/`sha` fields independently of each other, which the controller never disallows.

### Recommendation
- Require every org's `github_app` config to have a non-blank `webhook_secret` before accepting webhooks for it (fail closed instead of `return true unless webhook_secret`).
- In `WebhooksController#verify_signature`/`Handler`, verify that the org resolved for signature checking (`repository.owner.login`) actually owns the `Repository` derived from `repository.full_name` before dispatching, rejecting payloads where they disagree.
- Scope `StatusHandler#process` (and any other unscoped lookup) to commits belonging to a `Stack` under the verified organization's repositories rather than matching bare `sha` values globally.

### Proof of Concept
1. Operator configures two orgs in `secrets.yml`: `org-a` (no `webhook_secret` set, e.g. a dev/staging app install) and `org-b` (has `webhook_secret` set, and has a tracked `Stack` for `org-b/prod-repo`).
2. Attacker (no credentials) POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/anything" },
  "sha": "<sha of a commit in org-b/prod-repo tracked stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
Any `X-Hub-Signature` value is accepted because `Shipit.github(organization: "org-a").verify_webhook_signature` returns `true` unconditionally (no secret configured), per `lib/shipit/github_app.rb:76-83`.
3. `WebhooksController#create` dispatches to `StatusHandler`, which runs `Commit.where(sha: params.sha)` — matching the `org-b/prod-repo` commit regardless of the org used for signature verification — and creates a forged `success` status, potentially unblocking continuous deployment for `org-b/prod-repo` despite the attacker never having any credential for `org-b`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
