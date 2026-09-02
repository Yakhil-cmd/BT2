### Title
`StatusHandler` applies CI status to any commit row matching `sha` with no repository scoping, enabling cross-repository Status forgery via shared git history - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)`, across the entire `commits` table, and never reads or compares the payload's `repository.full_name`/`name` field against the commit's own stack repository. Because a fork legitimately shares ancestor commit SHAs with its upstream, a status webhook delivered for the attacker's fork can update the `Status`/`deployable?` state of the identical SHA as tracked in the upstream victim's Shipit stack.

### Finding Description
The broken binding, stated explicitly:
`Commit#sha` maps 1:1 to `(repository.full_name, sha)` == the CI Status recorded for a commit reflects a build result from the exact repository the owning Stack deploys from.

Trace:
- `app/controllers/shipit/webhooks_controller.rb` dispatches `event == 'status'` payloads to `Handlers::StatusHandler` after `verify_signature`, which only validates the HMAC using `Shipit.github(organization: repository_owner)` — i.e., it authenticates that the payload came from GitHub for *some* trusted organization. It never checks that the `repository.full_name` in the payload matches the repository that owns the SHA being updated. [1](#0-0) 
- `StatusHandler`'s params schema only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` — it does not even capture `repository`/`name` from the payload at all. [2](#0-1) 
- `process` resolves target commits purely by SHA, globally, with no stack/repository filter: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
- `create_status_from_github!` unconditionally writes a new `Status` row and recomputes `commit.status`/deployability via `add_status`, which can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` — i.e., it mutates the victim stack's merge/deploy eligibility state. [4](#0-3) [5](#0-4) 

Root cause: `sha` is indexed as `(stack_id, sha)` — i.e., uniqueness/lookup is scoped per stack in the schema/index, but the webhook handler ignores `stack_id`/repository entirely and queries across *all* stacks by `sha` alone. Since a public fork naturally shares ancestor commit SHAs with the upstream repository before divergence, any legitimately-signed `status` webhook for the attacker's own fork repository, containing a shared-ancestor SHA, will be applied to every `Commit` row with that SHA — including the one belonging to the victim's stack — even though the payload's `repository.full_name` names the attacker's fork, not the victim's repository.

Existing guards evaluated and found insufficient for this specific gap: `verify_signature`/`drop_unhandled_event` only assert webhook authenticity for a trusted GitHub organization, not repository identity of the target commit; the `ExplicitParameters` schema for `StatusHandler` doesn't constrain or even parse the repository field; there is no `Repository`/`Stack` level check inside `StatusHandler#process` comparing `commit.stack.repository` against the payload's originating repository.

### Impact Explanation
A successfully delivered `status` webhook for an attacker-controlled fork can silently rewrite the recorded CI `Status` (and therefore `deployable?`/merge eligibility) of the shared-ancestor commit as tracked by the upstream victim's Shipit stack — a payload for one repository mutating another's commit/stack state, which is a payload-for-one-repository-mutates-another's-record Critical-category impact. This is repeatable for any SHA that is shared between the attacker's repository and any tracked upstream stack (trivially true for the pre-fork common history, and for any commit an attacker cherry-picks/merges unchanged into their own fork). Blast radius is bounded to stacks whose commit history overlaps with a repository from which the attacker can cause a genuinely GitHub-signed status webhook to be delivered to the Shipit host.

### Likelihood Explanation
Exploitability is gated entirely on `verify_signature` succeeding, which depends on `Shipit.github(organization: repository_owner)` recognizing the organization named in the payload as one with a valid registered GitHub App/webhook secret. If the attacker's fork lives under an organization/account that is not configured in Shipit (the typical case for a "random public fork" under the attacker's personal account), `verify_signature` will raise `Shipit::GithubOrganizationUnknown` or fail HMAC verification, returning 422 before `StatusHandler` is ever reached — closing off the most naive version of this attack. I could not confirm from the available code whether the GitHub webhook secret used by `verify_webhook_signature` is scoped strictly per-organization/installation or could be shared across installations in a way that lets an attacker-owned fork under a *different* org still produce a validly-signed payload; this determines whether the attack is remotely triggerable by a fully external, unprivileged GitHub user, or requires the attacker to already have repo-creation rights inside the same trusted GitHub organization Shipit is configured for (a materially higher, though still sub-maintainer, privilege bar). Given the proof idea in the prompt explicitly bypasses the controller and calls `StatusHandler.call` directly, it deliberately skips over this precondition, but the *engine-code* defect — unscoped, repository-blind SHA lookup in `StatusHandler#process` — is real and independent of how the webhook was authenticated.

### Recommendation
Scope `StatusHandler#process` (and any commit lookup by `sha`) to only the stacks whose configured `repository` matches the payload's `repository.full_name`/`name`, e.g. `Commit.joins(:stack).merge(Stack.where(repository: Repository.from_github(params.name))).where(sha: params.sha)`, or otherwise reject/ignore statuses whose repository does not match the commit's owning stack before calling `create_status_from_github!`.

### Proof of Concept
minitest plan (model-level, matching the prompt's proof idea):
```ruby
test "StatusHandler must not update a commit belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit) # repository: "upstream/repo"
  shared_sha = "deadbeefcafef00dfeedfacefeedfacefeedface"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor")

  before_state = victim_commit.state # equality LHS: victim's Status before

  payload = OpenStruct.new(
    sha: shared_sha,
    state: "success",
    description: "attacker CI",
    context: "ci/attacker",
    branches: [],
    # attacker's fork, unrelated to victim_stack.repository
    name: "attacker/fork"
  )

  Shipit::Webhooks::Handlers::StatusHandler.call(payload.to_h.stringify_keys)

  after_state = victim_commit.reload.state # equality RHS: victim's Status after

  # Binding under test: before_state == after_state (attacker's repo must not affect victim's commit)
  assert_equal before_state, after_state, "StatusHandler updated a commit's status from an unrelated repository's webhook"
end
```
This demonstrates that `StatusHandler#process`'s global `Commit.where(sha: ...)` lookup, with no repository/stack scoping, allows the assertion to fail — proving the mutation occurs cross-repository purely from a shared SHA.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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
