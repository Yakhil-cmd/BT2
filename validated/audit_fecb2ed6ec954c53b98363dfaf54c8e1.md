## Title
Status webhooks are bound only by commit SHA, not by repository, allowing a payload from an attacker-controlled repo to satisfy `MergeRequest#all_status_checks_passed?` for a victim's PR - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `Commit.where(sha: params.sha)` with no scoping to the repository that the webhook's signature actually authenticates, so a `status` event legitimately signed for `attacker/repoA` writes a `Status` row on any `Commit` record in the entire Shipit instance sharing that SHA — including one that belongs to `victim/repoB`. Since git commit objects are content-addressed and fully attacker-controlled for their own commits, an attacker can trivially produce identical SHAs in two different repositories by pushing the same commit object to both.

### Finding Description
The claimed binding is: `Status` rows consumed by `MergeRequest#all_status_checks_passed?` via `head.statuses_and_check_runs` (`app/models/shipit/merge_request.rb:193-197`) == statuses whose webhook was verified as originating from the repository that owns `commit.stack` (i.e. `commit.stack.repository.full_name == payload.repository.full_name`). This binding is broken.

`app/controllers/shipit/webhooks_controller.rb:24-30` verifies the webhook signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the payload (`params.dig('repository', 'owner', 'login')`, line 59-62). This only proves the payload was signed by the GitHub App installed for that owner/org — it does not scope anything to a specific repository within that org, and more importantly, `StatusHandler#process` never checks the repository at all: [1](#0-0) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit#create_status_from_github!` writes the status using the commit's own `stack_id` ( [2](#0-1) ), regardless of which repository actually sent the webhook. `Commit` rows are looked up globally by `sha` only — there is no repository/owner column consulted in this handler.

Attack flow:
1. Attacker opens a PR against `victim/repoB`. Shipit creates/updates a `Commit` row for `victim/repoB`'s `MergeRequest#head` with `sha = X` via `MergeRequest#github_pull_request=` / `find_or_create_commit_from_github_by_sha!` (`app/models/shipit/merge_request.rb:247-260, 303-312`).
2. Because the attacker fully authored that commit, they know its exact tree, parents, author/committer identity and timestamps, and can push the byte-identical commit object to `attacker/repoA` (a repo they own), producing the same SHA `X` — this requires no cryptographic collision, just replaying the same git object.
3. Attacker triggers (or simply causes GitHub to send, e.g. by pushing a status via the Checks/Status API on their own repo) a `status` webhook for `attacker/repoA` with `sha: X, state: success`. This webhook is legitimately signed by GitHub for `attacker/repoA`'s installation, so `verify_signature` passes.
4. `StatusHandler#process` matches `Commit.where(sha: X)` across the whole database, finds the `victim/repoB` commit, and calls `create_status_from_github!`, writing a `Status` row under `victim/repoB`'s `stack_id`.
5. `MergeRequest#all_status_checks_passed?` on `victim/repoB` now sees a successful status and returns `true`; combined with `reject_unless_mergeable!` no longer rejecting on `ci_missing`/`ci_failing`, the merge queue (`Stack#schedule_merges`, driven by `stack.schedule_merges` in `Commit#add_status`, line 383) will proceed to call `MergeRequest#merge!`.

None of the existing guards prevent this: `verify_signature` authenticates the *organization*, not the specific repository-to-commit binding used inside the handler; the `ExplicitParameters` schema for `StatusHandler` only requires `sha`/`state`/etc., with no repository field validated against the target `Commit`'s stack; and `drop_unhandled_event`/`check_if_ping` are irrelevant to this path.

### Impact Explanation
An attacker who controls any repository (their own fork/personal repo) that shares Shipit's GitHub App installation can inject a fabricated "success" status onto an arbitrary victim stack's commit merely by controlling commit content and SHA equality, then triggering the merge queue to merge a PR into `victim/repoB` without the victim's actual required CI having passed. This is a cross-tenant authorization bypass leading to an unauthorized merge — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is repeatable against any stack/repository on the same Shipit instance for which the attacker can produce a colliding SHA, and scales across all tenants sharing one Shipit deployment.

### Likelihood Explanation
Preconditions: `victim/repoB` uses `merge_queue_enabled` with required status checks (as stated), and the Shipit instance's GitHub App/organization mapping includes an org/account the attacker controls a repo in (common for GitHub Apps installed org-wide or for public multi-tenant Shipit deployments). Attacker cost is low: crafting identical git commit objects across two repos they control is a standard git operation (no cryptographic SHA-1 collision needed — the attacker authors both instances of the content), and sending/triggering a status webhook from their own repo requires no special access. This is fully repeatable and does not require any Shipit secret, session, or privileged role.

### Recommendation
Scope `StatusHandler#process` (and equivalently `CheckRunHandler` if it has the same pattern) to the repository that sent the webhook, not just the SHA — e.g. join through `Commit#stack` and compare `stack.repository.full_name` (or owner/name) against the webhook payload's `repository.full_name` before applying the status, and skip/no-op otherwise. Alternatively, key `Commit` lookups by `(stack, sha)` scoped down to stacks whose configured repository matches the payload's `repository.full_name`.

### Proof of Concept
Minitest plan (`test/models/merge_request_test.rb` or new handler test):
1. Create two stacks: `stack_b` for `victim/repoB`, `stack_a` for `attacker/repoA` (or just create `stack_b` and a `Commit` for `attacker`'s content isn't even needed as a Shipit stack — only `victim/repoB`'s `Commit` with `sha: 'deadbeef...'` needs to exist).
2. Build `merge_request = shipit_merge_requests(:one)` (or create) on `stack_b` with `head` commit `sha: SHA`.
3. Assert baseline: `merge_request.all_status_checks_passed?` is `false` (no statuses yet).
4. Construct a `Webhooks::Handlers::StatusHandler` (or call `Commit.where(sha: SHA).each { |c| c.create_status_from_github!(...) }` directly, simulating the payload for `attacker/repoA`) with `state: 'success'`, `sha: SHA`.
5. Reload `merge_request.head`; assert `merge_request.all_status_checks_passed?` is now `true`, even though no status was ever produced by `victim/repoB`'s configured GitHub Apps/CI.
6. Assert this satisfies `reject_unless_mergeable!` returning `false` (no rejection), i.e. the merge-queue path would proceed to `merge!`, demonstrating the cross-repository forgery drives an unauthorized-merge decision.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
