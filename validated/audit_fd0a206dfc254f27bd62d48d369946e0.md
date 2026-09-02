### Title
Webhook signature verification is bound to an attacker-controlled `repository.owner.login` field, not to the repository/commit the handler actually mutates - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the HMAC against using an unverified field from the payload itself (`repository.owner.login`), [1](#0-0)  yet every event `Handler` subsequently mutates state using a completely different, independently-controlled field of the same unverified payload — `repository.full_name` for `PushHandler`, or, worse, no repository field at all for `StatusHandler`, which resolves purely by commit `sha`. [2](#0-1) [3](#0-2)  This breaks the equality `organization_used_for_signature_verification == organization/repository_that_gets_written`, exactly the class of trust-binding bug the report's `getWithdrawRequestValue()`/`price()` mismatch illustrates (a value trusted by one code path is never checked against the value another dependent code path actually consumes).

### Finding Description
`repository_owner` is read straight out of the JSON body before the signature is checked: [4](#0-3)  and used only to pick the `GithubApp` instance whose secret is used to verify the HMAC: [1](#0-0) 

`GithubApp#verify_webhook_signature` trivially returns `true` when that particular organization's `webhook_secret` is unset: [5](#0-4)  and Shipit explicitly documents leaving `webhook_secret` blank as a supported configuration, including in multi-organization installs. [6](#0-5) [7](#0-6) 

Once `verify_signature` passes, `handler.call(params)` is invoked with the **entire raw payload**, unconstrained by `repository_owner`. [8](#0-7)  The base `Handler` resolves the affected stacks from `payload.dig('repository', 'full_name')` — a field never checked against `repository_owner`: [2](#0-1) 

`StatusHandler` is the most exposed: it ignores the repository field entirely and matches commits purely by SHA across the whole `Commit` table, then writes a status onto them: [3](#0-2) 

`PushHandler` similarly uses `repository.full_name` to resolve `stacks` and calls `sync_github` on them: [9](#0-8) 

So in a multi-org install with Org B configured (per the documented pattern) without a `webhook_secret`, an unprivileged external attacker can:
1. Set `X-Github-Event: status`, and `repository.owner.login = "OrgB"` to make `verify_signature` select the secret-less app and pass unconditionally.
2. Set `sha`/`state`/`context` inside the body to target any commit tracked by Shipit belonging to Org A's repositories (which have their own real, secret-protected webhook), since `StatusHandler` performs no repository/owner check at all.

This writes a forged CI status onto Org A's commits despite never possessing Org A's `webhook_secret` — the "organization authenticated" (Org B, unsigned) is not the "repository/commit that is written" (Org A's commit).

### Impact Explanation
Forged commit statuses directly feed Shipit's `ci.require` gating and the merge queue, both of which decide whether a pull request can merge or a stack can auto-deploy. An attacker who can inject a fake passing status for a required CI context on an arbitrary tracked repository can push a stack past its CI gate, enabling an unauthorized deploy/merge on a repository the attacker has no legitimate write access to — this is a cross-repository write and can lead to an unauthorized deploy, matching the Critical impact tier. `PushHandler` reuse of the same unchecked `repository.full_name` additionally lets the same technique trigger `GithubSyncJob`/`stack.sync_github` on arbitrary stacks belonging to a different, properly-signed organization.

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations where at least one organization's `webhook_secret` is left blank — a configuration explicitly documented and supported by Shipit itself (`docs/setup.md`, `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`). Given this is a first-class documented deployment pattern rather than an obscure misconfiguration, the precondition is realistic for any Shipit instance onboarding multiple orgs incrementally (common while rolling out webhook secrets org by org). No credentials, GitHub App keys, or Shipit sessions are needed by the attacker.

### Recommendation
Bind the verified organization to the resource actually mutated: after `verify_signature` succeeds, re-derive `repository_owner` inside each `Handler` from the same trusted lookup used for verification, and reject/skip processing if `payload.dig('repository', 'owner', 'login')` (or `organization.login`) does not match the repository/commit's actual owning organization. In particular, `Handler#stacks` and `StatusHandler#process` must filter results to stacks/commits belonging to the same organization whose secret validated the request, not merely to `repository.full_name`/`sha` taken from the unauthenticated part of the trust decision.

### Proof of Concept
1. Deploy Shipit with two orgs configured per `docs/setup.md`'s "Using Multiple Github Applications" section: `OrgA` (real `webhook_secret`) tracking `OrgA/victim-repo`, and `OrgB` with `webhook_secret` left blank (as shown valid in `config/secrets.development.example.yml`).
2. POST to `/webhooks` with header `X-Github-Event: status` and JSON body:
```json
{
  "sha": "<sha of a commit already synced for OrgA/victim-repo>",
  "state": "success",
  "context": "ci/required-context",
  "repository": { "owner": { "login": "OrgB" } }
}
```
No `X-Hub-Signature` (or any arbitrary value) is required.
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` against the whole database, finds the OrgA commit, and creates a "success" status on it — despite the request never having been signed with OrgA's real webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
