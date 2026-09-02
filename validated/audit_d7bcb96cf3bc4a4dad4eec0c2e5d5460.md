### Title
Webhook signature check keys off `repository.owner.login` while handlers act on the unrelated `repository.full_name` field, and a blank per-organization `webhook_secret` makes verification a no-op - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate a request against using only `repository.owner.login` (or `organization.login`) from the JSON body, then verifies the raw payload's HMAC against that organization's configured secret. Every downstream handler, however, resolves the repository/stack to act on using a completely different, unchecked field: `repository.full_name`. Because `webhook_secret` is an optional, documented-as-nilable setting per organization, any organization left without one causes `GitHubApp#verify_webhook_signature` to unconditionally return `true`, regardless of the payload or its (missing/garbage) signature.

### Finding Description
`verify_signature` derives the authenticating organization purely from the payload itself and looks up a per-org app config: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially passes when no secret is configured for that org: [3](#0-2) 

Shipit explicitly supports per-organization configuration with an optional, nil-by-default `webhook_secret`, as shown in the setup docs and example secrets file: [4](#0-3) [5](#0-4) 

Every webhook handler, meanwhile, resolves the target `Repository`/`Stack` using `repository.full_name` - a field never cross-checked against the `repository.owner.login`/`organization.login` value used for authentication: [6](#0-5) [7](#0-6) [8](#0-7) 

The equality binding that should hold is: *organization whose signature was verified == organization owning the repository the handler writes to*. That binding is broken because (a) the two fields are read independently from the same attacker-supplied JSON body, and (b) for any org configured without a `webhook_secret`, verification is bypassed entirely (`return true unless webhook_secret`). The `/webhooks` endpoint requires no session, `ApiClient` token, or other credential - it is intentionally public, protected only by this signature check.

### Impact Explanation
An unauthenticated attacker who knows (or can trivially guess) the login of any organization configured on the Shipit instance without a `webhook_secret` can send a forged `push`, `status`, `check_suite`, or `pull_request` webhook where `repository.owner.login`/`organization.login` is set to that unsecured org while `repository.full_name` points at an entirely different, protected repository/stack. `verify_signature` passes trivially (blank secret), and the handler then acts on the attacker-chosen `full_name` target: `PushHandler` enqueues `stack.sync_github` (via `GithubSyncJob`) against arbitrary tracked stacks, `StatusHandler`/`check_suite` handlers forge commit statuses/check-run refreshes that gate deploy safety checks, and `PullRequest::*Handler`s manipulate review-stack provisioning for arbitrary repositories. This is a cross-repository write achieved without any credential, and depending on stack configuration (e.g., merge-on-green or auto-deploy behavior driven by synced status/check state) can influence which commits are considered deployable/mergeable - i.e., unauthorized cross-repository writes and potential influence over deploy/merge decisions.

### Likelihood Explanation
Exploitability requires only that at least one organization configured in the Shipit instance lacks a `webhook_secret` - a state the project's own example configuration and docs present as the default/normal case (`webhook_secret: # nil`). No credentials, sessions, or tokens are needed to reach `WebhooksController#create`, which is unauthenticated by design. The only "unknown" for the attacker is the login of an org configured without a secret, which is often discoverable (it's usually the org that owns the public-facing Shipit deployment itself).

### Recommendation
- Require a non-blank `webhook_secret` for every configured organization, and fail closed (reject the request) rather than treating a blank secret as an automatic pass in `GitHubApp#verify_webhook_signature`.
- Cross-validate that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` used to select the verifying `GitHubApp`, rejecting mismatched payloads before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `acme` (no `webhook_secret`) and `victim-org` (has a secret, hosts tracked stacks).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "acme" }, "full_name": "victim-org/protected-repo" }
}
```
No valid `X-Hub-Signature` is required since `acme` has no secret.
3. `verify_signature` resolves `repository_owner` = `acme`, looks up `Shipit.github(organization: "acme")`, and `verify_webhook_signature` returns `true` unconditionally (blank secret).
4. `PushHandler#process` runs `stacks` from `Repository.from_github_repo_name("victim-org/protected-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on a repository the attacker has no legitimate relationship to, with no signature ever validated against `victim-org`'s actual secret.

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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
