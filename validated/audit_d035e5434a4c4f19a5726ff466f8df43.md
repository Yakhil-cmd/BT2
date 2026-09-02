This confirms the vulnerability: `PushHandler`, `CheckSuiteHandler`, and other handlers scope their queries through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`), but `StatusHandler#process` does not — it queries `Commit.where(sha: params.sha)` unscoped by repository at all. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Cross-repository `Status` injection via unscoped SHA lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike every other handler (`PushHandler`, `CheckSuiteHandler`) which scope through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`). Because the `commits` table's uniqueness constraint is on `[sha, stack_id]` rather than `sha` alone, the same SHA can legitimately exist in multiple stacks (e.g. forked repositories, shared upstream history, template repos), allowing a webhook signed for repository A to write an attacker-controlled `target_url`/`description` onto a `Status` row belonging to a commit in unrelated stack B.

### Finding Description
The broken binding: `Status.target_url`/`description` shown on a commit belonging to stack B should equal a value that came from a payload verified against stack B's own GitHub organization/webhook credentials. Instead, `StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This query is global across the entire `commits` table, with no `WHERE stack_id IN (...)` or use of the `stacks` helper that other handlers rely on (`stacks` is derived from `Repository.from_github_repo_name(repository_name)` in `Handler#stacks`). `WebhooksController#verify_signature` only checks that the payload's signature is valid for the organization named in `params.dig('repository','owner','login')` — it does not verify that the specific commit SHA being modified actually belongs to that repository. Since `add_index :commits, %i(sha stack_id), unique: true` permits the same SHA to be attached to multiple different stacks (this happens naturally for forked repositories or shared history), any attacker who owns/controls a repository A that shares SHA history with victim repository B can trigger (or directly POST) a `status` webhook event, correctly signed for A's organization, whose `sha` matches a commit that also exists in stack B. `create_status_from_github!` will then create a `Status` on the commit as it exists in stack B, carrying the attacker's free-form `target_url`/`description`/`context` strings — fields which `ExplicitParameters` only validates as `String`, with no ownership or URL-safety check (`accepts :description, String` / `accepts :target_url, String`).

### Impact Explanation
An attacker who controls a GitHub repository that shares commit history with a victim's Shipit-tracked repository (a common situation: forks, templates, shared upstream) can inject arbitrary unauthenticated `target_url`/`description` content into a `Status` displayed under the victim's stack UI, attributed to the victim's commit without any indication it originated from a different repository. This is a cross-repository payload mutating another repo's stack/commit records, matching the "Critical: a payload for one repository mutating another's stack, commit" impact category. The attack is repeatable against any victim stack that shares SHA-identical commits with an attacker-controlled repository.

### Likelihood Explanation
Requires the attacker's repository to share at least one commit SHA with the victim's tracked stack — realistic via GitHub forks, "use this template" repos, or shared upstream branches, and does not require breaking SHA1/SHA256 hashing. The attacker needs no Shipit credentials; they only need push/webhook access to their own repository (satisfied by the given attacker capabilities) to trigger a `status` event that GitHub (or a direct forged request mimicking GitHub, if the attacker's org's webhook secret is known to them, which it is since it's their own repo) sends. Feasibility is moderate-to-high for organizations that manage many forked or templated repos under Shipit.

### Recommendation
Scope `StatusHandler#process` to commits within the stacks resolved from the webhook's own `repository_name`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This mirrors the pattern already used by `PushHandler`/`CheckSuiteHandler` and ensures a status payload can only mutate commits belonging to the repository that was cryptographically verified for that webhook.

### Proof of Concept
minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (or via `WebhooksControllerTest`):
1. Create two stacks/repositories, `stack_a` (attacker-owned) and `stack_b` (victim), each with their own `webhook_secret`/GitHub organization.
2. Create a `Commit` with `sha: "deadbeef"` under `stack_b` with `target_url: nil`.
3. Also create a `Commit` with the same `sha: "deadbeef"` under `stack_a` (simulating shared history, allowed by the `[sha, stack_id]` unique index).
4. Build a `status` webhook payload for `stack_a`'s repository containing `sha: "deadbeef"`, `target_url: "https://evil.example/attacker"`, signed with `stack_a`'s credentials only.
5. Post it through `Webhooks::Handlers::StatusHandler.call(payload)` (or via `WebhooksController#create` with signature verification stubbed only for stack A's org).
6. Assert: `Commit.find_by(sha: "deadbeef", stack_id: stack_b.id).statuses.last.target_url == "https://evil.example/attacker"` — proving stack B's commit received a status sourced from a payload verified only for stack A, violating the required binding that `Status.target_url` for stack B must originate from a payload verified for stack B's own webhook credentials.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
