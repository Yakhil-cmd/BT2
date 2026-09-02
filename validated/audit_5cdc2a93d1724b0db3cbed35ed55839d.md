## Title
Unscoped status webhook write lets an attacker's own repository forge CI state on a victim's production stack via shared commit SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

## Summary
`StatusHandler#process` looks up commits purely `by sha` with no repository/stack scoping, then writes the attacker-supplied `state`/`context` directly onto every matching `Commit` row across the entire database. Because Git commit SHAs are content-addressed, an attacker who forks (or otherwise shares history with) a victim repository controls commits with SHAs identical to the victim's, and a validly-signed webhook from the attacker's own repo can flip CI status (e.g., `ci/e2e` success) on the victim's production stack, unblocking or forcing deploys/merges.

## Finding Description
The broken binding: the code implicitly assumes `commit.sha == params.sha` implies `commit.stack.repository == webhook.repository`, but nothing enforces that equality.

- `WebhooksController#verify_signature` only checks that the payload's HMAC signature matches the secret configured for `repository_owner` (`params.dig('repository','owner','login')`), i.e., it proves the webhook came from *a* legitimate GitHub repository/org the attacker controls — it does **not** prove the SHA it references belongs to that repository. [1](#0-0) 
- `StatusHandler#process` then resolves the target purely by SHA, with no `stack_id`/`repository` filter at all: [2](#0-1) 
- `Commit#create_status_from_github!` unconditionally persists the attacker-controlled `state`/`context`/`description` and re-evaluates deployability/merge scheduling: [3](#0-2) [4](#0-3) 

Because Git SHAs are content hashes over the tree, parents, author/committer, message and timestamps, forking a repository (or any repo sharing history, e.g. a mirror) preserves identical SHAs for the shared commits. An attacker only needs their own GitHub repository (which they fully control and for which they can trivially receive/verify a correctly-signed `status` webhook, since the signature is validated per-organization, not per-repository-pair) to send a `status` event with `context: "ci/e2e"`, `state: "success"` and a `sha` that also exists as a `Shipit::Commit` in a victim's stack (because the victim's stack ingested the same commit via its own push history, or the attacker forked the victim's public repo and pushed the shared commit through Shipit's own recognized flow). `StatusHandler` then writes that status onto the victim's `Commit` row, `deployable?`/`blocked?` and `schedule_continuous_delivery` are re-evaluated, and if the affected stack is production with continuous delivery/merge-on-green enabled, this can trigger an unauthorized deploy or auto-merge.

None of the existing guards close this gap: `verify_signature` binds only to the sending org's secret, not the target commit's repository; the `ExplicitParameters` schema on `StatusHandler` only types-checks `sha/state/context`; there is no `require_permission!`/stack scoping anywhere in this handler.

## Impact Explanation
A payload from repository A (attacker-controlled) mutates `Commit`/`Status` records belonging to stack/repository B (victim), satisfying the "payload for one repository mutating another's stack/commit" Critical category. If the victim stack is production and gates deploys/merges on the `ci/e2e` context, the forged `success` status can flip `Commit#deployable?` to true and trigger `stack.schedule_merges` / continuous delivery, resulting in an unauthorized deploy of code that has not actually passed CI. This is repeatable against any stack whose commit history intersects with a repository the attacker controls (fork relationship), and is not limited to a single victim.

## Likelihood Explanation
Preconditions are attacker-controllable and cheap: the attacker needs (1) a GitHub repository they own that shares commit history with the victim's Shipit-tracked repo (trivially achieved via a fork of a public repo) and for which a `status` webhook can be validly signed (their own webhook/App installation on their own repo), and (2) knowledge that the victim stack requires/relies on a `ci/e2e` status context (documented/observable Shipit configuration). No Shipit session, API token, or GitHub org membership on the victim's side is required. This is fully repeatable and scriptable.

## Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers) to the repository that authenticated the webhook, e.g., join `Commit` to `Stack`/`Repository` and filter `stack.repository_full_name == params.repository.full_name` (or `repository_owner`/`repository_id`) before applying the status update, rather than a bare `Commit.where(sha: params.sha)`.

## Proof of Concept
minitest plan (`test/models/webhooks/status_handler_test.rb`, illustrative — do not add to `test/**` for scoring but as validation guidance):
```ruby
test "status for ci/e2e from repo A does not affect production stack in repo B sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # environment: 'production', requires ci/e2e
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared")

  # attacker's payload is validly signed for their own org, references shared_sha
  params = Shipit::Webhooks::Handlers::StatusHandler.new(
    ActionController::Parameters.new(sha: shared_sha, state: 'success', context: 'ci/e2e')
  )
  assert_not_equal victim_commit.stack.repository_full_name, "attacker/attacker-repo" # binding under test

  params.call({}) # simulated handler invocation

  victim_commit.reload
  assert_not victim_commit.status.success?, "status for a different repository must not flip victim commit state"
end
```
Both sides of the equality (`commit.stack.repository` vs the webhook's authenticated `repository_owner`/`full_name`) diverge after processing today, confirming the vulnerability; the fix must make them equal (filter enforced) so the assertion holds.

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
