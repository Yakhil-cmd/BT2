Based on my investigation, I found a valid analog matching the "organization authenticated vs. repository written" binding class.

### Title
Webhook signature verification authenticates the payload's claimed organization while all event handlers act on an unrelated, attacker-supplied repository — allowing cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App/organization config to use for HMAC verification purely from a payload field, and then hands the *entire raw payload* to the handlers without re-validating that the org used for authentication matches the repository the handler subsequently mutates.

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
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

Every downstream handler, however, never looks at `repository.owner.login` — it resolves the *target* repository/stack solely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`Repository.from_github_repo_name` splits `owner/name` from that field and looks the record up directly:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [3](#0-2) 

`repository.owner.login` (used for signature/org selection) and `repository.full_name` (used to find the Stack acted on) are two independent JSON fields in the same body — nothing in the code enforces that `full_name` starts with `owner.login`. The binding the app relies on — "the organization whose secret authenticated this request" == "the repository whose state is written" — is never checked.

Also relevant: signature verification is a no-op when an organization has no configured `webhook_secret` (a supported configuration shown in the shipped sample configs):
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 
```yaml
someothergithuborg:
  ...
  webhook_secret: # nil
``` [5](#0-4) 

### Impact Explanation
For any GitHub organization/app configuration mounted on this Shipit instance that has `webhook_secret` unset (a documented, supported state, not a misconfiguration outside the code's design — `verify_webhook_signature` explicitly treats it as "always verified"), `verify_signature` passes unconditionally regardless of `X-Hub-Signature`. An unauthenticated network attacker (no session, no `ApiClient` token, no `webhook_secret`, no GitHub App key, no repository access) can then POST an arbitrary JSON body directly to the public `/webhooks` endpoint with:
- `repository.owner.login` (or `organization.login`) set to the no-secret org, to pass `verify_signature`, and
- `repository.full_name` set to `"OtherOrg/other-repo"` — any repository tracked by this Shipit instance, regardless of which organization it belongs to.

Handlers such as `StatusHandler`/`CheckSuiteHandler`/`PushHandler`/the `PullRequest::*Handler` family (all inheriting `Handler#stacks`/`#repository_name`) will then act on `OtherOrg/other-repo`'s Stacks: writing forged `Status`/commit-status records that feed into `Commit#deployable?` (a safety gate consulted when triggering deploys), forcing `GithubSyncJob` runs, and archiving/unarchiving/creating Review Stacks for pull requests on a repository the attacker has no access to. This is a cross-organization write authorized by the wrong organization's credential — the exact binding break called out in scope ("an organization that authenticated versus the repository that is written").

### Likelihood Explanation
Requires only that one configured GitHub App/org on the instance has no `webhook_secret` set — an explicitly supported code path (`return true unless webhook_secret`), reachable by any unauthenticated actor who can send an HTTP POST to the public webhooks endpoint, with no credentials, tokens, or privileged access of any kind.

### Recommendation
After resolving `repository_owner` for signature verification, re-derive the authenticated organization and assert it matches the owner segment of `payload.dig('repository', 'full_name')` (and any `organization.login` used) before dispatching to handlers, so the org whose secret authenticated the request is provably the same org that owns the repository being mutated. Do not allow `verify_webhook_signature` to unconditionally return `true` for an org with no configured secret if any other configured org in the same deployment does have a secret — surface a hard failure/log instead of silent pass-through.

### Proof of Concept
1. Instance is configured with two orgs: `OrgA` (no `webhook_secret`, as shown supported in `config/secrets.development.shopify.yml`) and `OrgB` (has stacks tracked, e.g. `OrgB/prod-service`, and may or may not have a secret).
2. Attacker (unauthenticated) sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "OrgB/prod-service", "owner": { "login": "OrgA" } }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally — the forged signature header is never actually checked.
4. `StatusHandler` (via `Handler#repository_name` = `payload.dig('repository','full_name')` = `"OrgB/prod-service"`) resolves `OrgB`'s real stacks and writes a forged `success` status against the victim commit, altering `Commit#deployable?` for a repository the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L15-18)
```yaml
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
```
