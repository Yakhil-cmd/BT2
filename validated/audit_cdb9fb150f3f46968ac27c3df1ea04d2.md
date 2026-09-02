### Title
Webhook signature is verified against the org named in `repository.owner.login`, but every handler acts on the different `repository.full_name` field, allowing a trusted-org-scoped attacker to forge events for repositories they don't own - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to check the HMAC signature against using `repository_owner` (derived from `params.dig('repository','owner','login')`), while `Shipit::Webhooks::Handlers::Handler#repository_name` (and every concrete handler) resolves the actual `Repository`/`Stack` to mutate using the sibling field `payload.dig('repository','full_name')`. These two payload fields are never checked for consistency, so a Shipit installation configured for multiple GitHub organizations (a supported, documented mode) will happily accept a payload whose signature-selection field names an org the attacker controls while its action field names a completely different, victim-owned repository.

### Finding Description
`verify_signature` picks the verification key based on an attacker-controlled JSON field: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `config/secrets.yml` (multi-org support is explicitly documented via `secrets.github.<org>.webhook_secret`): [3](#0-2) [4](#0-3) 

The HMAC comparison itself is a straightforward per-secret check, with no binding to the repository being acted on: [5](#0-4) 

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the **entire raw payload** to handlers: [6](#0-5) 

Every handler resolves the target `Repository` from a *different* field, `repository.full_name`, not `repository.owner.login`: [7](#0-6) [8](#0-7) 

`PushHandler` and `StatusHandler` then act directly on the resolved `Stack`/`Commit`: [9](#0-8) [10](#0-9) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature` (`repository.owner.login`) **≠** `repository/stack acted on by handlers` (`repository.full_name`).

**Before the attacker's request:** for any legitimate GitHub webhook, `repository.owner.login` and the owner segment of `repository.full_name` are always the same value, because GitHub itself populates both fields from the single repository being pushed/updated — the equality holds naturally.

**After the attacker's request:** the attacker directly POSTs a JSON body to `/webhooks` (this endpoint is unauthenticated by design — it only requires a valid HMAC, not a Shipit session or `ApiClient` token) with:
```json
{"ref":"refs/heads/master","after":"<attacker sha>",
 "repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"}}
```
signed with `attacker-org`'s own `webhook_secret` (which the attacker knows, because they are the administrator of `attacker-org`'s GitHub App — a Shipit-supported, unprivileged-relative-to-victim organization). `repository_owner` resolves to `attacker-org`, the signature check passes against `attacker-org`'s secret, but `PushHandler`/`StatusHandler` resolve the affected `Repository` via `repository.full_name = "victim-org/victim-repo"`, letting the attacker drive github-sync or fabricate commit statuses on a repository/organization they neither own nor administer.

### Impact Explanation
This crosses the organization-authentication vs. repository-written binding explicitly called out as in-scope. Concretely:
- `StatusHandler#process` calls `commit.create_status_from_github!(params)` for any commit matching `params.sha`, letting the attacker inject a forged CI status (e.g. flip a required check to `success`) on a victim repository/stack, which can unblock deploys or auto-merges gated on `ci.require` — an unauthorized-deploy-adjacent state modification of a repository the attacker has no authorization over.
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)`, forcing a re-sync of the victim stack toward an attacker-chosen SHA/branch state.

Both are triggerable purely by knowing a secret the attacker legitimately possesses for their *own* onboarded organization, with zero footprint on the victim org (no GitHub webhook secret leak, no Shipit session, no `ApiClient` token needed) — this is a cross-repository/cross-organization state-write, matching the report's "authenticated-thing vs. acted-on-thing" mismatch class from the analog report.

### Likelihood Explanation
Requires a Shipit deployment configured with the multi-organization `github:` schema (explicitly documented and supported: `config/secrets.development.shopify.yml`, `lib/shipit.rb#github_app_config`). Any organization onboarded to such a shared Shipit instance can mount this against any other onboarded (or even non-configured, if `repository_owner` falls back oddly) organization's stacks, since the two fields are attacker-supplied and never cross-validated anywhere in the request path.

### Recommendation
After successfully verifying the signature, re-derive the organization actually referenced by `repository.full_name` (the field every handler uses) and reject the request if it doesn't match the organization whose secret was used to verify the signature (i.e., enforce `repository.owner.login.downcase == repository.full_name.split('/').first.downcase` before dispatching to handlers), or simplify by always deriving both the verification key and the acted-upon repository from the single `repository.full_name` field.

### Proof of Concept
1. Shipit is configured for two orgs, `attacker-org` (attacker-administered GitHub App, `webhook_secret` known to attacker) and `victim-org` (has a tracked `Stack` for `victim-org/victim-repo`).
2. Attacker computes `sha1=HMAC-SHA1(attacker_org_webhook_secret, raw_body)` for:
```json
{"ref":"refs/heads/master","after":"<attacker_controlled_sha>",
 "repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"}}
```
3. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and verifies successfully against the attacker's own secret. [11](#0-10) 
5. `PushHandler` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker_controlled_sha>')` on the victim's stack, despite the request never being signed by `victim-org`. [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
