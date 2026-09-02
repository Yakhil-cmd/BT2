### Title
Webhook signature verification key is selected from `repository.owner.login`, but handlers act on an unchecked `repository.full_name` (or no repository binding at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GithubApp`/`webhook_secret` to verify the HMAC against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Once the signature check passes, the actual webhook handlers (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) resolve the target repository/commit from an entirely different field — `repository.full_name` in `Handler#repository_name`, or, in `StatusHandler`, from a global, repository-unscoped `Commit.where(sha: params.sha)` lookup. Nothing enforces that the organization used to select the verification secret matches the organization actually being written to.

### Finding Description
The binding that should hold is: **organization authenticated == repository written**.

- `WebhooksController#verify_signature` selects the app config via `repository_owner`, then verifies `X-Hub-Signature` against that org's `webhook_secret`: [1](#0-0) [2](#0-1) 

- `GithubApp#verify_webhook_signature` explicitly returns `true` (no check at all) when the selected org has no `webhook_secret` configured: [3](#0-2) 

- Shipit is explicitly designed to host multiple GitHub organizations in one instance, each with its own (optionally blank) `webhook_secret`: [4](#0-3) 

- Once the request passes `verify_signature`, `WebhooksController#create` dispatches the *whole* payload to handlers, and every handler resolves its target from fields the signature-selection step never used: [5](#0-4) [6](#0-5) 

`PushHandler` uses `repository_name` (i.e., `repository.full_name`) to find the `Repository`/`Stack` to sync — a field independent from `repository.owner.login` used for signature selection: [7](#0-6) 

`StatusHandler` is worse: it performs **no repository scoping whatsoever**, resolving directly from a global `Commit.where(sha: params.sha)`: [8](#0-7) 

`CheckSuiteHandler` similarly resolves via `stacks` (repository-scoped by `full_name`), independent of the org used for signature verification: [9](#0-8) 

Before/after the attacker's request:
- **Before**: The equality `organization authenticated == organization/repository written` is expected to hold implicitly because in a normal GitHub-originated webhook, `repository.owner.login` and `repository.full_name` always describe the same repository.
- **After**: An attacker who controls (or whose target org has) an entry in `Shipit.github` config with a blank/known `webhook_secret` can submit a POST directly to `/webhooks` with `repository.owner.login` set to that low-trust org (satisfying `verify_signature`) while setting `repository.full_name` (for push/check_suite) or `sha` (for status, unscoped) to reference a completely different, unrelated repository/stack managed by the same Shipit instance. The equality is broken: the org that "authenticates" the request is not the repository being acted upon.

### Impact Explanation
This crosses a credential/authentication boundary between tenants of the same Shipit instance:
- Via `PushHandler`, an attacker can force `stack.sync_github(expected_head_sha:)` on any stack/branch belonging to a repository they don't control, by only satisfying signature verification for an unrelated (low-trust or secret-less) org.
- Via `StatusHandler`, since there is no repository check at all, an attacker who can pass `verify_signature` for *any* configured org can forge a commit status (`create_status_from_github!`) for **any** commit sha in **any** repository/stack tracked by the instance — this can manipulate deploy readiness/gating (`deployable_status`) used to decide whether a deploy can proceed, which maps to "unauthorized deploy" territory.
- This qualifies as High/Critical: cross-repository writes / unauthorized deploy influence, achieved purely by exploiting the mismatch between the field used for signature-key selection and the fields used for target resolution — no `ApiClient` token, GitHub App private key, or session is required, only the ability to produce a validly-signed (or unsigned, if `webhook_secret` is blank for some configured org) payload for `POST /webhooks`.

### Likelihood Explanation
Likelihood is elevated by two independent factors documented in-repo:
1. Multi-org configuration is a first-class, documented deployment pattern (`config/secrets.development.shopify.yml`), meaning a real deployment plausibly has multiple orgs with differing trust levels sharing one Shipit instance.
2. `webhook_secret` is explicitly optional (`# nil` in both example config files), and `verify_webhook_signature` treats a blank secret as automatically verified — so an org administrator or GitHub App owner who simply didn't configure a secret for one org creates a skeleton key affecting every other org's repositories/stacks on the same instance.

### Recommendation
- In every webhook handler (`Handler#stacks`/`repository_name`, `StatusHandler`, `CheckSuiteHandler`, etc.), require that the resolved repository's owner matches the organization that was used to select/verify the webhook signature (i.e., cross-check `repository.owner.login` against the app/org actually used in `verify_signature`), not just resolve by `full_name` or `sha` alone.
- Scope `StatusHandler`'s `Commit.where(sha:)` lookup by the repository derived from the verified organization, not a global, cross-repository query.
- Do not silently return `true` from `verify_webhook_signature` when `webhook_secret` is blank; require every configured organization to have a secret, or explicitly fail closed for organizations without one.

### Proof of Concept
1. Shipit instance is configured (as documented) with two orgs, e.g. `attacker-org` (no `webhook_secret` set, or a secret the attacker controls because they own that org's GitHub App) and `victim-org` (contains the real target stack/repo).
2. Attacker crafts a POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies the signature against `attacker-org`'s secret (which the attacker knows, or which is blank), so the request passes.
4. `PushHandler#process` resolves `repository_name` from `repository.full_name` = `"victim-org/victim-repo"`, and calls `sync_github(expected_head_sha:)` on that stack — a repository the attacker never proved ownership/authorization for.
5. Equivalently, for `StatusHandler`, the attacker only needs a valid `sha` value (e.g., a public commit SHA from the victim repo) — the handler performs no repository check at all, so a status can be forged for that commit regardless of which org's signature was used.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
