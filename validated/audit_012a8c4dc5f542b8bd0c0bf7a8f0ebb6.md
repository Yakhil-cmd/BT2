### Title
Cross-organization/cross-repository writes via webhook signature binding mismatch between `repository.owner.login` (verified) and `repository.full_name`/`sha` (acted upon) - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). The actual event handlers, however, resolve the target `Repository`/`Stack`/`Commit` from a *different* field of the same payload — `payload.dig('repository', 'full_name')` in `Handler#repository_name`, or an unscoped `sha` lookup in `StatusHandler#process`. Nothing in the code enforces that the owner used to pick the verifying secret actually matches the owner embedded in `full_name`, or that a `sha` belongs to a commit tracked under that organization at all.

### Finding Description
`verify_signature` computes: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

This selects a per-organization `github_app`/`webhook_secret` via `Shipit.github(organization: repository_owner)` and raises `GithubOrganizationUnknown` if unrecognized, which confirms this engine supports multiple, independently-configured GitHub organizations (multi-tenant), each with its own `webhook_secret`.

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full JSON body to handlers such as `PushHandler`. The base `Handler` resolves the write target independently of the field used for signature verification: [3](#0-2) 

`PushHandler#process` then syncs whatever stack matches that `full_name`/branch: [4](#0-3) 

`StatusHandler#process` is worse — it doesn't even use a repository scope, only a bare commit `sha`: [5](#0-4) 

Because HMAC verification covers the raw JSON body but the code never cross-checks that `repository.owner.login` (used to pick the verifying secret) is consistent with `repository.full_name` (used to pick the write target) or with an arbitrary `sha`, an org that legitimately owns its own webhook secret in a multi-org Shipit deployment can forge a payload signed with its own secret while setting `repository.full_name` (or `sha`) to point at a stack/commit that belongs to a completely different organization onboarded to the same Shipit instance.

This breaks exactly the trust binding the rules call out: `repository_owner` (organization authenticated by the verified signature) ⧧ `repository.full_name`/`sha` (repository/commit actually written by the handler).

### Impact Explanation
This yields cross-repository writes: an attacker who legitimately administers one org/repo onboarded into a shared Shipit instance can trigger `GithubSyncJob` on another organization's stack (forcing a `sync_github` against an `expected_head_sha` of their choosing), or inject an arbitrary `Commit`/`create_status_from_github!` write on any commit `sha` tracked anywhere in the instance, regardless of organization — without ever needing the victim organization's `webhook_secret`, `ApiClient` token, or repository write access. This matches the "Critical - cross-repository writes" impact bucket.

### Likelihood Explanation
Requires only that the attacker control (as a legitimate tenant) one organization's webhook secret in a multi-org Shipit deployment — a normal, documented capability, not a privileged escalation within Shipit itself. No social engineering, TLS interception, or host compromise needed; only crafting a JSON payload with mismatched `repository.owner.login` vs `repository.full_name`/`sha` and computing the HMAC with the attacker's own known secret.

### Recommendation
After signature verification, re-derive the acting organization from the same field used for verification and require handlers to validate that `repository.full_name`'s owner segment (or the resolved `Repository`'s owner) matches `repository_owner`. For `StatusHandler`, scope the `Commit` lookup by the repository resolved from the verified organization instead of a bare, unscoped `sha`.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` (per `Shipit.github(organization:)` lookup in `lib/shipit/github_app.rb`).
2. Attacker controls `org-a`'s webhook secret (e.g., as its GitHub org admin, having legitimately registered `org-a/some-repo` in Shipit).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: push`, HMAC-signed with `org-a`'s secret, but with body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": { "full_name": "org-b/victim-repo", "owner": { "login": "org-a" } }
}
```
4. `verify_signature` computes `repository_owner = "org-a"`, verifies successfully against `org-a`'s secret.
5. `PushHandler#repository_name` reads `full_name = "org-b/victim-repo"`, resolves `org-b`'s stacks, and enqueues `GithubSyncJob` against `org-b`'s stack with the attacker-chosen `expected_head_sha` — a cross-organization write the attacker was never authorized to trigger.

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
