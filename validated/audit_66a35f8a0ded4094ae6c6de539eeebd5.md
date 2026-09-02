### Title
Webhook signature verification is keyed to `repository.owner.login`/`organization.login`, but event handlers act on the independent `repository.full_name` field — unauthenticated cross-repository webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to check against based on a payload field (`repository.owner.login`, falling back to `organization.login`), while the handlers invoked afterwards (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolve the target `Stack`/`Repository` from a *different* payload field, `repository.full_name`. Nothing ties these two fields together, so the "organization whose signature was authenticated" and "the repository that gets written to" are two independently attacker-controlled values inside the same unsigned-relationship JSON body.

### Finding Description
`verify_signature` picks the verifying organization purely from payload content: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only enforces a signature at all when a `webhook_secret` is configured for that resolved organization: [3](#0-2) 

Downstream, every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target repository from a completely different field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [4](#0-3) 

Shipit's documented multi-organization configuration allows some organizations to be configured without a `webhook_secret` (`webhook_secret: # nil`) while others have one: [5](#0-4) 

Because `verify_signature`'s organization-selection field (`repository.owner.login`/`organization.login`) is independent from the field the handler uses to select the actual `Stack` (`repository.full_name`), an unauthenticated caller can craft a single payload where:
- `repository.owner.login` (or `organization.login`) = an organization configured **without** a webhook secret, so `verify_webhook_signature` returns `true` unconditionally, and
- `repository.full_name` = a **different**, secret-protected organization's repository that Shipit tracks.

The request passes `verify_signature` (no secret required for the "authenticating" org) but the handler that runs afterwards (e.g. `PushHandler#process`, `StatusHandler#process`) operates on the victim repository resolved from `repository.full_name`, completely bypassing that repository's actual webhook secret. This is precisely the "organization authenticated" vs. "repository written" binding break: `repository_owner (verified) ≠ repository.full_name (acted upon)`.

### Impact Explanation
An unauthenticated attacker (no Shipit session, no `ApiClient` token, no webhook secret for the targeted org) can forge webhook events against any repository/stack tracked by a Shipit instance that also tracks at least one organization without a configured webhook secret. Concretely:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)` for the victim stack based on attacker-chosen `ref`/`after`, forcing arbitrary sync state [6](#0-5) .
- `StatusHandler` writes attacker-controlled commit statuses (`state`, `context`, `target_url`) onto real commits via `Commit#create_status_from_github!`, which feeds into deploy-eligibility/commit-check gating shown in `commit_checks_controller.rb`/`stack.rb` [7](#0-6) .

Forged, favorable CI statuses on a protected repository's commits can make a commit appear "safe to deploy" when it has not actually passed CI, directly undermining the deploy-gating trust boundary and enabling an unauthorized/unsafe deploy decision — meeting the High-impact bar ("escalation ... unauthenticated ... task streams" / contributing to an unauthorized deploy).

### Likelihood Explanation
Requires: (1) a Shipit instance configured for multiple GitHub organizations (documented, supported configuration), (2) at least one of those organizations configured without a `webhook_secret` (also a documented, valid configuration state), and (3) the victim organization/repository also being tracked by the same instance. No secret, token, session, or privileged access is needed by the attacker — only knowledge of the login of the no-secret org and the `full_name` of the target repository, both of which are typically public information (GitHub org/repo names). This makes it plausible in real deployments that mix "public/low-trust" and "protected" organizations behind one Shipit instance.

### Recommendation
Bind the signature verification to the same repository identity the handler will act on: derive `repository_owner` from the same `repository.full_name` field used by `Handler#repository_name` (rather than a separately-read `repository.owner.login`/`organization.login`), and reject the request if these are inconsistent. Alternatively, require a `webhook_secret` for every configured organization and refuse to process an event whose resolved `Repository`'s owning organization does not exactly match the organization whose secret validated the signature.

### Proof of Concept
1. Shipit instance is configured for two GitHub orgs: `open-org` (no `webhook_secret` set) and `secure-org` (has `webhook_secret`), both with repos tracked as Shipit stacks.
2. Attacker (no credentials) POSTs to `/webhooks` with header `X-Github-Event: push` (or `status`) and body:
```json
{
  "organization": { "login": "open-org" },
  "repository": { "owner": { "login": "open-org" }, "full_name": "secure-org/protected-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` = `"open-org"` from `repository.owner.login`, calls `Shipit.github(organization: "open-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` with no signature check at all.
4. `PushHandler#process` runs, resolving the target via `payload.dig('repository', 'full_name')` = `"secure-org/protected-repo"`, and calls `stack.sync_github(expected_head_sha: params.after)` on the protected stack — despite `secure-org` having its own webhook secret that was never checked.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
