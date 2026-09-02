### Title
Unscoped `Commit.where(sha:)` write in `StatusHandler#process` lets a status from one repository flip deployability/blocking on any other stack sharing the same commit SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository or stack scoping, then writes a GitHub status onto every matching `Commit` row. Because the `commits` table only enforces SHA uniqueness per stack (not globally), two different repositories/stacks can legitimately hold `Commit` rows with an identical `sha` (e.g., via fork history or independently created rows sharing ancestry), and a `status` webhook authenticated for one repository will be applied to the other stack's commit as well, changing `deployable?`/`blocked?`/merge scheduling for a tenant that never authenticated that webhook.

### Finding Description
The broken binding is the implicit assumption that `Commit#sha` uniquely identifies a commit belonging to the repository that authenticated the incoming webhook: `webhook.repository == commit.stack.repository` for every `commit` matched by `params.sha`. This does not hold.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit.where(sha: params.sha)` is a bare, global query with no `stack_id`/repository filter. GitHub webhook signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only proves the payload came from the GitHub App tied to *some* repository; it does not constrain which `Commit` rows the handler is allowed to touch. Once the handler runs, `commit.create_status_from_github!(params)` calls `add_status`, which recomputes `Status::Group.compact` and, on a `simple_state` change, calls `stack.schedule_merges if new_status.pending? || new_status.success?` and fires `deployable_status`/`commit_status` hooks. [2](#0-1) [3](#0-2) 

`Commit#deployable?` and `#blocked?` are computed purely from `status`/`stack.blocking_statuses`, driven directly by whatever `Status` rows exist for that commit, regardless of which repository wrote them:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [4](#0-3) 

Exploit flow: attacker controls or registers a repository in Shipit whose commit history shares one or more commits (identical SHA1) with a victim repository/stack - the most common case being a GitHub fork, where ancestor commits carry identical SHAs in both repos and both can independently end up as `Commit` rows in Shipit (e.g. via each repo's own PR/push events). The attacker triggers (or has GitHub trigger) a `status` webhook for their own, correctly-signed repository with `context: ci/circleci`, `state: success` for that shared SHA. `StatusHandler` finds *every* `Commit` row with that SHA - including the victim stack's row - and writes the status onto it, flipping `deployable?`/`blocked?` and invoking `stack.schedule_merges` for the victim stack.

None of the existing guards stop this: `verify_signature` only checks the HMAC for the sending repository, not which `Commit` rows may be updated; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, `context`, etc.), not ownership; there is no `require_permission!`/`stacks` scope check inside `StatusHandler`; and `Repository`/`Stack` model validations don't constrain `Commit#sha` uniqueness across stacks.

Note: the "review_stacks_enabled false + provisioning-precedence bug" referenced in the question (`OpenedHandler#provision?` in `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70`, where `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)` only gates the first `allow_all` branch on `review_stacks_enabled` due to Ruby `&&`/`||` precedence) is a real, separate defect, but it is not required to reproduce the impact described here: [5](#0-4)  `StatusHandler`'s missing scoping alone is sufficient to flip `deployable?`/`blocked?`/trigger merges on any stack (review-stack-enabled or not) that happens to share a commit SHA with the attacker's authenticated repository.

### Impact Explanation
A `status` webhook honestly signed for repository A can change the deployability/blocking state and trigger `stack.schedule_merges` for a completely unrelated stack in repository B, as long as both have a `Commit` row with the same `sha` - a payload for one repository mutating another's stack/commit, matching the "Critical" impact category (unauthorized deploy/merge/block driven by cross-tenant data injection). The blast radius covers any Shipit installation where multiple repositories/stacks can share commit history (forks, mirrored repos, monorepo splits), and is repeatable per shared SHA and per status context configured as `required_statuses` on the victim stack.

### Likelihood Explanation
Preconditions: attacker needs a repository registered with Shipit (or one that can deliver a genuinely GitHub-signed `status` webhook to the Shipit host) that shares commit ancestry with the victim's repository/stack, and the victim stack must require `ci/circleci` as part of its required/blocking statuses. Forks with shared history are extremely common on GitHub, and the attacker only needs push access and status-setting rights on their own repository (unprivileged w.r.t. the victim). No Shipit secrets, sessions, or API tokens are needed beyond what GitHub already grants for signing the attacker's own repository's webhooks. This makes exploitation practically feasible and repeatable, not merely theoretical, since it does not depend on brute-forcing a SHA1 collision - only on natural commit-history overlap.

### Recommendation
Scope `StatusHandler#process` (and the analogous `CheckRunHandler`, if present) to the repository that authenticated the webhook, e.g. resolve `Commit` via `stack.repository` (or `github_repo_name`) derived from `params.repository`/`params.name` in addition to `sha`, instead of a bare `Commit.where(sha: params.sha)`. Additionally, fix the operator-precedence bug in `OpenedHandler#provision?` by parenthesizing `repository.review_stacks_enabled && (...)` around the whole expression so `review_stacks_enabled` gates all three provisioning behaviors, not only `allow_all`.

### Proof of Concept
```ruby
test "status webhook for one repository's commit does not affect another stack's commit sharing the same sha" do
  repo_a = shipit_repositories(:shipit) # attacker-authenticated repo
  stack_a = repo_a.stacks.create!(environment: "attacker-env")
  stack_b = shipit_repositories(:cyclimse).stacks.create!(environment: "victim-env") # unrelated repo/stack
  stack_b.update!(required_statuses: ["ci/circleci"])

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared ancestor")
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared ancestor")

  # Binding under test: webhook.repository == commit.stack.repository
  assert_not_equal commit_a.stack.repository, commit_b.stack.repository

  before = commit_b.reload.deployable?

  Shipit::Webhooks::Handlers::StatusHandler.new(
    repository: repo_a.full_name,
    sha: shared_sha,
    state: "success",
    context: "ci/circleci"
  ).process

  after = commit_b.reload.deployable?

  refute_equal before, after # victim stack's commit deployability changed from an unrelated repo's webhook
end
```

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
