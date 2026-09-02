### Title
Cross-tenant status webhook injection via unscoped `Commit.where(sha:)` lookup - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Finding Description
The broken binding: `authenticated_repository(webhook) == repository_owning(matched_commit)` — this is **false**.

`WebhooksController#verify_signature` correctly verifies that an inbound `status` webhook was genuinely signed for the organization named in the payload's own `repository.owner.login` field: `Shipit.github(organization: repository_owner)` looks up the app config for that org and HMAC-verifies the signature against it. [1](#0-0) [2](#0-1)  This is a legitimate check — it does correctly bind the signature to *some* org that is genuinely the sender. The flaw is downstream: it only proves the payload came from the org named in its own `repository` field, but the handler that then acts on the payload never re-checks that field against the record it mutates.

`StatusHandler#process` ignores the `repository` field entirely and instead resolves the target purely by SHA, globally across the whole installation:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit#create_status_from_github!` → `add_status` then unconditionally schedules merges for whichever stack owns the matched commit row, based only on the (attacker-controlled) `state`:
```ruby
stack.schedule_merges if new_status.pending? || new_status.success?
``` [4](#0-3) [5](#0-4) 

`schedule_merges` enqueues `ProcessMergeRequestsJob.perform_later(stack)` against **that stack**, not the stack tied to the org that authenticated the webhook.

Exploit path: an attacker who owns a repo under "Org B" (registered with the same Shipit instance) can construct a git commit whose SHA1 collides with a real commit already queued on "Org A"'s stack. Git commit SHA1 is fully deterministic from its content (tree, parents, author/committer name/email/date, message) — if the attacker can read Org A's public commit metadata, they can reproduce an identical commit object (e.g., a squash/empty commit with matching metadata) and push it into their own Org B repo, then trigger a genuine, validly-signed `status` event for that SHA (e.g., via their own repo's status API/integration) with `state: 'pending'`. The webhook is correctly signed for Org B, passes `verify_signature`, but `StatusHandler#process`'s SHA-only lookup also matches the identically-shaed row belonging to Org A's stack, and mutates it — enqueuing `ProcessMergeRequestsJob` for Org A's stack and re-evaluating `Stack#next_commit_to_deploy`/`deployable_commits` based on attacker-forged state, with no involvement or authorization from Org A.

No existing guard (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema on `StatusHandler`) checks that the matched `Commit#stack`'s repository matches the webhook's authenticated `repository_owner`/`full_name`. The `ExplicitParameters` schema only validates `sha`/`state`/etc. types, not repository ownership. [6](#0-5) 

### Impact Explanation
A validly-authenticated webhook for repository/org B can write a `Status` row and drive `Commit#status`/`deployable?` state for a commit belonging to Org A's stack, and enqueue `ProcessMergeRequestsJob.perform_later(org_a_stack)`, which reads and can merge/reject Org A merge requests without Org A's authorization. This is a payload for one repository mutating another tenant's stack/commit/merge-request state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Repeatable against any commit whose SHA the attacker can reproduce (fully deterministic if commit metadata is known/public), and generalizable to any other handler resolving records by SHA/branch-name alone without repository scoping.

### Likelihood Explanation
Requires: (1) the target Shipit instance to host multiple GitHub orgs/tenants sharing one installation, (2) the attacker to control a repo registered under a distinct org on that same instance, and (3) the attacker to know/reproduce the exact commit metadata (tree, parents, author/committer identity+timestamp, message) of a targeted Org A commit to collide the SHA1 — feasible when Org A's repo/commits are public, since Git SHA1 is a pure deterministic hash of that metadata (no signing/nonce). No secrets, sessions, or tokens are needed beyond the attacker's legitimate control of their own Org B repository/webhook. This is a real, exploitable, low-cost condition — not a brute-force SHA1 collision.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving records solely by SHA/branch/etc.) to the repository that authenticated the webhook: filter `Commit.where(sha: params.sha)` by joining through `Stack` and matching `stack.repository.owner`/`full_name` against `params.repository.full_name` (or the verified `repository_owner`), rejecting/ignoring matches outside that repository.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook for repo B's SHA does not mutate a commit belonging to unrelated stack A" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create_stack(repository: create_repository(owner: 'org-b', name: 'repo-b'))

  colliding_sha = 'deadbeef' * 5
  commit_a = stack_a.commits.create!(sha: colliding_sha, message: 'shared content commit')

  params = ExplicitParameters::Params.new(sha: colliding_sha, state: 'pending')

  assert_no_enqueued_jobs(only: ProcessMergeRequestsJob) do
    # Simulates a webhook that legitimately authenticated for org-b's repo, not stack_a's org.
    Shipit::Webhooks::Handlers::StatusHandler.new(stack_b, params).process
  end

  commit_a.reload
  assert_not_equal 'pending', commit_a.status.state
end
```
Both sides of the equality: `stack_b (authenticated by webhook signature)` vs. `stack_a (actually mutated by StatusHandler#process via unscoped Commit.where(sha:))` — currently diverge, confirming the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
