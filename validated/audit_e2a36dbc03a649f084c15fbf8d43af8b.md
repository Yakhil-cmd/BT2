### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, while the repository actually mutated is selected from the unrelated, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to check the HMAC against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), but every event `Handler` (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target `Stack`/`Repository` using a completely different, independently-controlled JSON field: `payload.dig('repository','full_name')`. The signature never actually covers the binding "this organization's secret authorizes writes to this repository". [1](#0-0) [2](#0-1) 

### Finding Description
`WebhooksController` is a public, unauthenticated Rails endpoint; the only gate is `verify_signature`:

```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [3](#0-2) 

`repository_owner` is read straight out of the attacker-supplied JSON body:
```
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [4](#0-3) 

`GitHubApp#verify_webhook_signature` treats a blank/unset `webhook_secret` as automatically verified:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [5](#0-4) 

`webhook_secret` is an optional, documented setting (`webhook_secret: # nil`) in both the single-org and multi-org config examples, so an installation running with it unset is a supported, documented configuration, not a "not mounted as documented" case. [6](#0-5) [7](#0-6) 

Once past `verify_signature`, every handler ignores `repository.owner.login` entirely and instead resolves the target repository/stack using `repository.full_name`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`PushHandler#process` then syncs commits for whatever stack this resolves to, and `StatusHandler#process` writes a `Status` for any local commit matching `params.sha`, regardless of which "organization" was used to satisfy `verify_signature`: [8](#0-7) [9](#0-8) 

Equality that is broken: `organization authenticated by verify_signature == organization owning the repository that Handler#stacks actually mutates`. Before an attacker's request, this equality trivially holds because legitimate GitHub deliveries fill both fields consistently. After a crafted POST directly to `/webhooks`, an attacker sets `repository.owner.login`/`organization.login` to any org configured with no `webhook_secret` (or one whose secret they know), while setting `repository.full_name` to `victim-org/victim-repo` — a repository/stack belonging to a completely different, "protected" organization already registered in this Shipit instance. `verify_signature` passes (because it only ever checked the attacker-chosen org), yet the handler mutates the victim repository's `Stack`/`Commit` records.

### Impact Explanation
This breaks the deployment-trust binding "GitHub organization authenticated by the webhook signature must equal the repository whose Shipit state is mutated." Concretely:
- `StatusHandler` lets the attacker forge a commit status (`state: 'success'`) for any SHA already known to Shipit on the victim stack, which can satisfy CI-gating (`ci.require`) checks and enable an **unauthorized deploy** of that commit.
- `PushHandler` can trigger `sync_github` for a victim's stack/branch, causing Shipit to re-sync from GitHub using attacker-influenced timing/`expected_head_sha`, interfering with deploy state for a repository the attacker has no access to.

Both land squarely in the accepted High/Critical impact categories ("cross-repository writes" / "an unauthorized deploy"), because they cross a repository/organization boundary that the signature check was supposed to enforce.

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (public HTTP endpoint gated only by HMAC), so no GitHub credentials, session, or `ApiClient` token are required — satisfying the "unprivileged attacker" requirement. The only precondition is that at least one organization configured on the instance has no `webhook_secret` (a documented, supported default) or that the attacker otherwise knows one org's secret; multi-tenant Shipit installs (as shown in `config/secrets.development.shopify.yml`) are an explicit supported deployment shape where this mismatch becomes directly exploitable across organizations.

### Recommendation
Bind the signature verification to the same field used for the actual write: verify the request using the organization/owner derived from `repository.full_name` (not from a separately supplied `repository.owner.login`/`organization.login`), or, after computing `repository_owner` for secret lookup, assert `repository_owner == payload.dig('repository','full_name')&.split('/')&.first` (and equivalent for organization events) before dispatching to handlers. Additionally, treat a blank `webhook_secret` as "reject all webhooks for this org" rather than "accept all", or require an explicit opt-in flag to run without a secret.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `attacker-org` (no `webhook_secret` set) and `victim-org` (has a `Stack` registered, e.g. `victim-org/victim-repo`), as in `config/secrets.development.shopify.yml`.
2. As an anonymous attacker, POST directly to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "organization": { "login": "attacker-org" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<known victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` calls `Shipit.github(organization: 'attacker-org')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` is needed.
4. `StatusHandler#process` then runs `Commit.where(sha: params.sha)` for the victim stack (resolved via `repository.full_name`) and creates a forged successful status, potentially unblocking a CI-gated deploy of `victim-org/victim-repo` that the attacker never had access to.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** config/secrets.development.shopify.yml (L5-14)
```yaml
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
