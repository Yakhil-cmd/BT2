### Title
Cross-repository commit status forgery via unscoped `StatusHandler` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the GitHub App configured for the *organization/repository that sent it* [1](#0-0) . However, `StatusHandler#process` never checks that the commit it mutates actually belongs to the repository that was authenticated — it looks up commits by SHA alone, across the entire Shipit instance [2](#0-1) . This breaks the equality "organization that authenticated == repository whose commit state is written."

### Finding Description
The webhook pipeline is:
1. `WebhooksController#verify_signature` derives `repository_owner` from the payload and verifies the HMAC signature using that organization's `webhook_secret` [3](#0-2) . This proves the payload genuinely originates from a GitHub App installation on that organization/repository — nothing more.
2. `WebhooksController#create` then dispatches the parsed JSON to the registered handler for the event type [4](#0-3) .
3. Most handlers correctly re-derive the acted-upon repository from the same signed payload via `Handler#stacks`/`Handler#repository_name`, which scopes lookups to `Repository.from_github_repo_name(repository_name)` [5](#0-4) . `PushHandler` and `CheckSuiteHandler` both use this repository-scoped `stacks` helper before touching any commit [6](#0-5) [7](#0-6) .
4. `StatusHandler`, however, ignores the `repository` field entirely and mutates *any* commit row in the database whose `sha` matches the payload's `sha`, with no ownership filter: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [8](#0-7) .

Git SHAs are only guaranteed unique within a repository's own history, not globally. Forks, shared upstream history, cherry-picked/rebased commits, or even coincidentally identical trees produce identical SHAs across unrelated repositories tracked by the same Shipit instance. Additionally, GitHub's Commit Status API allows a repository owner to post a status for *any* 40-hex-character SHA on their own repo — the SHA does not need to correspond to a commit that actually exists in that repo. This means an attacker who legitimately controls a repository/organization with the Shipit GitHub App installed (an "unprivileged" caller with respect to Shipit itself — no Shipit session, ApiClient token, or victim-repo access) can:
- Discover the SHA of a commit in a victim stack tracked by the same Shipit instance (commit SHAs are public/discoverable via the GitHub UI/API or via Shipit's own public pages).
- Call GitHub's Status API on their own repository with that SHA, which delivers a `status` webhook signed with their own org's legitimate `webhook_secret`.
- Shipit verifies the signature successfully (because it correctly matches the sending org), then `StatusHandler` writes the forged status onto the victim's `Commit` row, since the lookup has no repository/stack scoping.

This is the direct analog of the Arcadia bug: there, liquidity was cached from one context (`assetToLiquidity[assetId]`) and used later without re-verifying it still matched the actual on-chain state for that exact position, letting an attacker manipulate a value that didn't belong to them. Here, the webhook signature verifies the sender's identity/organization, but the handler acts on a resource (`Commit`) selected only by an attacker-influenced key (`sha`) that is never checked against the same organization/repository binding.

### Impact Explanation
Commit statuses drive Shipit's merge queue and deploy gating logic (required/blocking statuses, `MergeRequest` revalidation). A forged "success" status on a victim's commit can cause Shipit to treat a required CI check as passed, enabling an unauthorized merge or unblocking a deploy that should have been gated by real CI results. This falls under the "unauthorized deploy, rollback, or merge" High/Critical impact category, and requires no privileged access to the victim's Shipit stack, GitHub repository, or Shipit account — only that the attacker controls some other repository whose webhooks are also configured against the same Shipit instance.

### Likelihood Explanation
Requires: (a) a multi-tenant/shared Shipit instance where the attacker's own repo/org has the Shipit GitHub App installed (a documented supported multi-org configuration [9](#0-8) ), and (b) knowledge of a target commit SHA tracked by another stack on that instance. Both are attacker-obtainable without any credential theft. The exploit itself is a single legitimate GitHub API call (create a commit status) — no signature forging, no secret theft, no exploitation of Shipit auth internals.

### Recommendation
Scope `StatusHandler#process` to the repository identified in the signed payload, mirroring `Handler#stacks`/`PushHandler`/`CheckSuiteHandler`: resolve `stacks` (or the owning `Repository`) from `payload.dig('repository', 'full_name')` first, and only update `commit.create_status_from_github!` for commits that belong to a stack under that repository — e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker controls repo `attacker/toy-repo`, which has the same shared Shipit installation's GitHub App installed (legitimate multi-org config).
2. Attacker looks up a commit SHA `abc123...` belonging to `victim/prod-repo`, tracked as a `Commit` row in the same Shipit instance.
3. Attacker calls `POST /repos/attacker/toy-repo/statuses/abc123...` via the GitHub API with `state: success`, `context: "required-check"`.
4. GitHub delivers a `status` webhook to Shipit, signed with `attacker`'s org webhook secret. `WebhooksController#verify_signature` succeeds because it correctly matches `attacker`'s org.
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, matches the `victim/prod-repo` commit row (no repository filter), and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto the victim's commit — potentially satisfying a required/blocking status check used by the merge queue for `victim/prod-repo`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
