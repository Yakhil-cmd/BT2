## Finding

The vulnerability is real and confirmed in the code.

### Broken binding

The intended binding is: **a `Status` row written for `stack_id: S`** should imply **the webhook that created it was verified using `stack S`'s own GitHub organization's webhook secret**.

In `app/models/shipit/webhooks/handlers/status_handler.rb`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit.where(sha: params.sha)` is **global**, not scoped to the repository/organization that sent the webhook. The `commits` table has a unique index on `["sha", "stack_id"]` [1](#0-0)  — meaning the exact same SHA is explicitly permitted to exist as separate `Commit` rows under *different* `stack_id`s (e.g. a fork's stack and the upstream's stack, since forks share commit history and SHAs are content-addressed). The handler iterates over **every** such row and calls `create_status_from_github!(params)` on each [2](#0-1) , which delegates to `Status.replicate_from_github!` writing `context`/`state`/`target_url` from the attacker-controlled payload with no cross-check against which org/repo actually owns that commit [3](#0-2) .

### Path from attacker's request

1. `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [4](#0-3) . This only proves the payload was signed by *the attacker's own org* (since GitHub signs webhooks per-installation for whatever repo/org they belong to) — it says nothing about which `Commit`/`stack_id` rows get mutated downstream.
2. `WebhooksController#create` dispatches to `StatusHandler.call(params)` for any `status` event that passes that per-attacker-org signature check [5](#0-4) .
3. `StatusHandler#process` looks up commits by SHA **only**, with no `stack_id`/`repository` filter [2](#0-1) .
4. If a victim stack already tracks a `Commit` row with that same SHA (plausible via a fork, cherry-pick, or shared history — this is exactly why `[sha, stack_id]` rather than `[sha]` is unique in the schema [6](#0-5) ), the attacker's own-org-signed payload creates a `Status` row for the **victim's** `stack_id` with attacker-chosen `context`/`state`.
5. `MergeRequest::StatusChecker#required_statuses` / `Status::Group` then evaluate the victim's PR against `deploy_spec.merge_request_required_statuses` [7](#0-6)  and `app/models/shipit/status/group.rb:24-31`, and can find a matching forged `success` status, satisfying `all_status_checks_passed?` [8](#0-7) .

None of the referenced guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`, model validations on `Status`/`Commit`) check that the target `Commit`'s `stack_id` actually belongs to the organization that produced the signature — the signature check and the record-mutation scope are on two different axes (org-of-signature vs. sha-only-lookup).

### Impact / Likelihood

An attacker who owns any repository whose commit history intersects (shares a SHA) with a target stack's commit history — most simply, a fork of the victim's repo — can forge a `status` webhook signed under their own org and inject a `Status` record into the victim stack tied to a shared-SHA `Commit`. This is a **cross-tenant, unauthorized write** satisfying a merge/deploy CI gate for a repository the attacker never authenticated against, matching the Critical impact category ("a payload for one repository mutating another's ... commit ... resulting in an unauthorized ... merge").

### Recommendation

Scope `StatusHandler#process` (and analogous handlers) by the repository/stack derived from the webhook's own `repository` payload, e.g. resolve the target `Stack` via `repository.full_name`/`repository_owner` first, then only touch `stack.commits.where(sha: params.sha)`, rather than a global `Commit.where(sha: ...)`.

### Proof of Concept (test plan)

In `test/controllers/webhooks_controller_test.rb`-style minitest, no live GitHub:
1. Create two stacks, `victim_stack` (org `victim-org`) and `attacker_stack` (org `attacker-org`), each with a `Commit` row sharing the same `sha`.
2. Set `victim_stack.cached_deploy_spec` with `merge_request_required_statuses` including `ci/required-check`.
3. Create a `MergeRequest`/head commit on `victim_stack` pointing at that shared SHA; assert `all_status_checks_passed?` is `false` initially (no status yet).
4. POST a `status` webhook payload with `repository.owner.login = 'attacker-org'`, `sha` = shared SHA, `context: 'ci/required-check'`, `state: 'success'`, stubbing `Shipit.github(organization: 'attacker-org').verify_webhook_signature` to return `true` (simulating attacker's own valid signature).
5. Assert that `victim_stack`'s `Commit` (not just the attacker's) now has a `Status` with `context: 'ci/required-check'`, `state: 'success'`.
6. Assert `merge_request.all_status_checks_passed?` (or `StatusChecker#required_statuses` check) is now `true` — proving the victim's required-status gate was satisfied by an attacker-signed, attacker-authored payload.

### Citations

**File:** test/dummy/db/schema.rb (L79-86)
```ruby
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/merge_request.rb (L37-39)
```ruby
      def required_statuses
        deploy_spec&.merge_request_required_statuses || []
      end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
