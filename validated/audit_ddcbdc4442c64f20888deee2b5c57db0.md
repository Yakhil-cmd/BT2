### Title
Cross-tenant commit status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `params.sha` with no repository/stack predicate, unlike `PullRequest::OpenedHandler` and `PushHandler`, which both scope through `repository.review_stacks` / `stacks` derived from `payload['repository']['full_name']`. Because a Git SHA is content-addressed and not globally unique to one Shipit stack/repository, an attacker who can emit a `status` webhook referencing a SHA that also exists in another tenant's stack (e.g. a shared/forked commit) can write a fabricated commit status onto that other tenant's `Commit` record.

### Finding Description
Binding claimed: repository-scoping in `Handler#repository_name`/`Handler#stacks` (used by `PushHandler#process`, `app/models/shipit/webhooks/handlers/push_handler.rb:13`) and in `OpenedHandler#process` via `repository.review_stacks` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:45`, `repository` resolved at lines 50-54 from `params.repository.full_name`) should equal the scoping present in `StatusHandler#process`. Tracing `StatusHandler`: [1](#0-0) 

The `params` block never declares `requires :repository`, and `process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with zero reference to `payload['repository']`, `repository_name`, or `stacks`. This confirms the equality is false: scoping is present in the sibling handlers and absent here.

The base `Handler` class provides the scoping primitives that `StatusHandler` chooses not to use: [2](#0-1) 

`Commit#create_status_from_github!` unconditionally mutates the matched commit's statuses regardless of which repository's webhook triggered it: [3](#0-2) 

Root cause: the DB uniqueness constraint on `commits` is `(sha, stack_id)` unique, not `sha` unique globally — i.e. the schema explicitly permits the same SHA to exist across multiple stacks/repositories: [4](#0-3) 

Exploit flow: an attacker owns/controls a repository (or fork) that is wired to send `status` webhooks to the Shipit host (per the stated threat model, this is an assumed-reachable capability, same class of access used to open PRs/push branches). They send a `status` event whose `sha` matches a commit that also exists in a victim tenant's stack — trivially achievable when the victim's repository is a fork/mirror of, or shares commit history with, the attacker's repository (identical trees produce identical SHAs), or when an initial/empty/cherry-picked commit is reused. `StatusHandler#process` finds *all* `Commit` rows with that `sha` across every stack in the installation and writes the attacker-supplied `state`/`description`/`target_url` onto them via `create_status_from_github!`, which can flip `deployable?`/CI-gating status and trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` for the victim's stack — none of which the attacker is authorized to touch.

Existing guards do not prevent this: webhook signature verification (`GitHubApp#verify_webhook_signature`) only proves the payload came from a GitHub App delivery for *some* installed repository, not that the `sha` inside belongs to that repository; the `ExplicitParameters` schema for `StatusHandler` has no `repository` requirement to enforce at parse time; and there is no `Repository`/`Stack` predicate anywhere in `process` to reject cross-repo matches.

### Impact Explanation
A payload originating from one (attacker-controlled) repository mutates another tenant's `Commit`/status state — this is the "payload for one repository mutating another's stack/commit" Critical category. Impact per request: forged/poisoned commit status on an arbitrary victim stack's commit, which can unblock or block deploys (`deployable?`, `blocked?`), and trigger merge scheduling (`stack.schedule_merges`) or deployable-status hooks for a stack the attacker never authenticated against. This is repeatable against any commit SHA that collides across stacks, and the blast radius spans every tenant stack sharing that commit history on the same Shipit installation.

### Likelihood Explanation
Preconditions: the attacker needs a repository capable of sending a `status` webhook to the Shipit host (assumed reachable per the given threat model, analogous to the PR/push capabilities already granted) and a SHA collision with a commit tracked by a victim stack — realistically achievable via forks/mirrors of the same upstream history, common base/empty commits, or cherry-picked identical trees, all of which are cheap and repeatable for an attacker with no special privileges, tokens, or secrets.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`OpenedHandler`: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to that repository's stacks (e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or `Commit.where(sha: params.sha, stack: stacks)`), mirroring `Handler#stacks`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, model-level, no live GitHub):
1. Create two stacks/repositories `repo_a` and `repo_b`, each with a `Commit` sharing the identical `sha` value (allowed since uniqueness is `(sha, stack_id)`).
2. Build a `status` payload whose `repository.full_name` (if present at all) is `repo_a`'s name (or omit `repository` entirely, since it's not required).
3. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process`.
4. Assert: `repo_b`'s commit's `statuses`/`status.state` changed to the attacker-supplied state, even though the payload never named/authenticated `repo_b`. Contrast: performing the analogous cross-repo payload against `PullRequest::OpenedHandler` raises via the `requires :repository` schema validation, demonstrating the asymmetry.
5. Assert equality check: before fix, `StatusHandler#process` has no call to `stacks`/`repository_name`; after the recommended fix, the same payload against `repo_a` mutates only `repo_a`'s commit and leaves `repo_b`'s commit status untouched.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
