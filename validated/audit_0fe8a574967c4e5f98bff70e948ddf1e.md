### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no repository/stack scoping, then calls `create_status_from_github!` on every match. Because the `commits` table is indexed on `(stack_id, sha)` rather than `sha` alone, multiple stacks (potentially backed by different GitHub repositories, e.g. forks or repos sharing history) can hold `Commit` rows with the identical `sha`. A status payload validly signed for one repository therefore mutates commit status state belonging to an unrelated stack/repository.

### Finding Description
The broken binding is: `status.context/state for repository A` should equal `status.context/state applied only to commits belonging to repository A`, i.e. `commit.stack.github_repo_name == payload.repository.full_name` for every `Commit` mutated. In `StatusHandler#process`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

there is no filter tying the lookup to the repository that authenticated the webhook. The only repository-aware check in the pipeline is `WebhooksController#verify_signature`, which selects the correct GitHub App/secret using `repository_owner` from the payload purely to validate the HMAC signature — it never constrains which `Commit`/`Stack` rows the handler is allowed to touch:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
end
``` [2](#0-1) 

The `commits` table's DB index is `(stack_id, sha)` (per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), not a unique index on `sha` alone, confirming the schema itself permits multiple stacks to record `Commit` rows for the same `sha` (e.g. commits shared via forks, mirrored repos, or monorepos split into multiple stacks). `Commit#blocked?` and `#deployable?` depend on the status computed from `statuses`/`check_runs` written by `create_status_from_github!`:

```ruby
def blocked?
  return false if stack.blocking_statuses.empty?
  stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
end

def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [3](#0-2) 

Exploit flow: an attacker owns/controls a repository (e.g. a fork of the victim's repo that still shares a historical commit `sha`) with the Shipit GitHub App installed. They set a commit status on that sha in their own repo via the GitHub API (`context: ci/kubernetes`, `state: failure`). GitHub signs and delivers the `status` webhook using the attacker's own repository/organization credentials, which passes `verify_signature` legitimately (it is a real, correctly signed event — just for the wrong repository from the victim's perspective). `StatusHandler#process` then matches `Commit.where(sha: params.sha)`, which returns the victim stack's `Commit` row for the same `sha`, and writes the forged `failure` status onto it, flipping `blocking?`/`blocked?` and thus `deployable?` for the victim's stack — with `blocking_statuses` configured to require `ci/kubernetes`, this blocks (or, with a subsequent forged `success`, unblocks) deploys/merges on the victim stack.

None of the existing guards prevent this: `verify_signature` only authenticates *that GitHub sent this payload for some repository*, not that the `sha` in the payload belongs to the repository whose stack is being mutated; `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of the payload, not repository ownership of the `sha`.

### Impact Explanation
A payload authenticated for repository A can flip `blocking?`/`blocked?`/`deployable?` state for a `Commit` belonging to stack/repository B, gating or forcing deploys and merges the attacker does not control. This is a payload-for-one-repository-mutates-another's-commit/stack scenario, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is repeatable against any victim stack whose commits share a `sha` with a repository the attacker controls (most practically, forks of the victim repository, or split monorepo stacks), and the attacker can toggle the forced status back and forth at will.

### Likelihood Explanation
Preconditions: (1) attacker owns/controls a GitHub repository with the Shipit GitHub App installed (satisfied by "push to a fork" / "any internet user who can send HTTP requests… emit webhooks from a repository they own"), (2) a `sha` exists in both the attacker's repo and the victim's stack's commit history (trivially achievable by forking before divergence, or in split-monorepo Shipit setups where multiple stacks track the same underlying repository/commits), (3) the victim stack has `blocking_statuses` configured for `ci/kubernetes` (a documented, common Shipit feature). No secrets, sessions, or privileged roles are required — only the ability to set a commit status on a commit the attacker legitimately owns. This is low-cost and fully repeatable.

### Recommendation
Scope `StatusHandler#process` (and equivalent handlers) to the repository that authenticated the webhook, e.g. filter `Commit.joins(:stack).merge(Stack.where(repo_name: payload_repo_name, repo_owner: payload_repo_owner))` before applying `sha` matches, ensuring a `Commit` is only updated if its owning stack's repository matches the payload's `repository.full_name`.

### Proof of Concept
minitest (`test/models/webhooks/status_handler_test.rb`, hypothetical scope fix validation):
```ruby
test "status for a sha shared across repositories only updates the matching repository's commit" do
  victim_stack = shipit_stacks(:shipit) # repo_owner: "shopify", repo_name: "shipit-engine"
  victim_stack.update!(...) # configure blocking_statuses to include "ci/kubernetes" via deploy spec stub
  attacker_stack = create_stack(repo_owner: "attacker", repo_name: "fork-of-shipit")

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  before = victim_commit.reload.blocked?
  # Payload authenticated for attacker's repo only
  Handlers::StatusHandler.new(sha: shared_sha, state: "failure", context: "ci/kubernetes").process

  after = victim_commit.reload.blocked?
  assert_equal before, after, "victim commit's blocked? must not change from a status authenticated for a different repository"
end
```
Assert equality of `victim_commit.blocked?` before/after processing a status payload authenticated only for `attacker_stack`'s repository; failing this assertion (state changes) demonstrates the cross-tenant mutation.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
