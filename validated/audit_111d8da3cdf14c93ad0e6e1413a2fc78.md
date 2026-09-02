Confirmed: the base `Handler` class provides a `stacks` helper that scopes lookups to the repository named in the webhook payload via `Repository.from_github_repo_name(repository_name)&.stacks`, but `StatusHandler#process` does **not** use it — it queries `Commit.where(sha: params.sha)` directly, with no repository/stack scoping at all. [1](#0-0) [2](#0-1) 

### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a webhook from any repository mutate commit status on any other stack sharing that SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire database instead of scoping to the repository that authenticated the webhook, unlike the `stacks` helper available in the base `Handler` class. Any repository whose GitHub organization/App is registered in Shipit (so `verify_signature` passes) can send a `status` webhook that writes a status onto a `Commit` row belonging to a completely different stack/tenant, provided the SHA matches (trivially achievable via a fork sharing git history, or a cherry-picked/re-authored commit with identical content).

### Finding Description
The broken binding: the code assumes `status.sha ∈ Repository(status.payload.repository).stacks.commits` (i.e., a status for `ci/lint` only ever touches commits belonging to the repo that sent the webhook), but the actual query is `Commit.where(sha: params.sha)` with no repository predicate at all — so in truth `status.sha` is matched against `Commit` rows from *every* stack in the installation.

Path: `POST /webhooks` → `WebhooksController#create` → `verify_signature` (checks HMAC against `Shipit.github(organization: repository_owner)`'s webhook secret — this proves the payload came from a repo under a *registered* GitHub organization/App, not that it came from the *specific victim repository*) → `Shipit::Webhooks.for_event('status')` → `StatusHandler.call(payload)` → `StatusHandler#process`: [1](#0-0) 

Contrast with the base class, which exists specifically to scope lookups to the sending repository: [3](#0-2) 

`StatusHandler` bypasses this helper entirely. Once a matching `Commit` row is found in the victim's stack, `commit.create_status_from_github!(params)` writes the status: [4](#0-3) 

This flows into `add_status`, which recomputes `Status::Group`, emits `deployable_status`/`commit_status` hooks, and calls `stack.schedule_merges` when the new status becomes `success`/`pending`: [5](#0-4) 

For a stack configured with continuous delivery, the same commit's `schedule_continuous_delivery` (triggered on create, but re-evaluated by anything gating on `deployable?`) checks `deployable?`, which depends on the very statuses attacker just forged: [6](#0-5) [7](#0-6) 

**Exploit flow:** Attacker owns/controls a repository under any GitHub organization already registered with Shipit's GitHub App (satisfying `verify_signature`, which only validates the HMAC using that org's secret — it does not verify the sending repository owns the target commit). Attacker forks a public victim repository (or otherwise obtains a commit with an identical SHA to one present in the victim's stack — trivial for forks since git SHAs are content-addressed and shared history yields identical hashes). Attacker triggers a real GitHub `status` event for `context: ci/lint` on that SHA from their own repo/org (e.g., via their own CI or a manual API call against their own repo, which GitHual will happily deliver to Shipit if the app is installed there). GitHub signs and delivers the webhook; `verify_signature` passes because the signature is valid for the attacker's own org. `StatusHandler#process` then matches the SHA against `Commit.where(sha: ...)` and finds the row belonging to the **victim's** stack, applying the attacker-controlled state/context to it — flipping `ci/lint` to success (unblocking a deploy) or failure (blocking a deploy) on a stack the attacker never authenticated against.

**Why existing guards fail:** `verify_signature` authenticates *which organization's secret signed the payload*, not *which repository's commit the payload is entitled to mutate* — it never cross-checks `payload.dig('repository','full_name')` against the `Commit`'s owning `Stack`/`Repository`. `drop_unhandled_event` only checks the event type is registered, not the payload contents. The `ExplicitParameters` schema for `StatusHandler` only validates presence/type of `sha`, `state`, `context`, etc. — it has no relation to authorization. No model validation exists to reject a status write from a mismatched repository because `Commit#create_status_from_github!` has no notion of "requesting repository" at all.

### Impact Explanation
An attacker who controls (or forks) a repository already onboarded to the same Shipit GitHub App installation can, via a single unauthenticated webhook, write an arbitrary CI status (`ci/lint`, or any required/blocking context) onto a commit belonging to an unrelated victim stack, as long as a SHA collision exists (achievable deterministically via forking). This directly matches the Critical category "a payload for one repository mutating another's stack, commit, task or team," and can result in an unauthorized deploy (flipping a blocking status to success unblocks `deployable?` and can trigger `schedule_merges`/continuous delivery) or an unauthorized block/rollback (flipping to failure halts deploys). The `bot_login`/`Shipit.user` detail from the question only affects *whose identity* the resulting auto-triggered deploy runs as; it is not required for the core cross-tenant write, which is the root vulnerability. Blast radius spans every stack sharing the compromised GitHub App/organization registration, i.e., potentially many tenants in a multi-repo Shipit deployment.

### Likelihood Explanation
Preconditions: attacker needs a repository under a GitHub organization/App already registered in Shipit (common in multi-tenant/org-wide installations), and a commit SHA that also exists in the victim's tracked history — trivially obtained by forking a public victim repo (shared commit ancestry preserves identical SHAs) or replaying an existing commit. No Shipit credentials, session, or API token are required; the only requirement is the ability to trigger a real GitHub `status` event from the attacker's own repo, which any repo owner/collaborator can do (via their own CI, GitHub Checks API, or `POST /repos/{owner}/{repo}/statuses/{sha}` with their own token). This is inexpensive and fully repeatable against any victim stack whose commits share history with a repo the attacker controls under the same GitHub App scope.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the `stacks` helper in the base `Handler` class — e.g., resolve `stacks` from `payload.dig('repository','full_name')` and restrict the commit lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status can only mutate commits belonging to stacks tied to the repository that sent it.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status is scoped to the sending repository" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack!(repository: create_repository(name: 'attacker/repo'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'x', author: AnonymousUser.new)
  # attacker's repo independently has a Commit row with the same sha (fork / shared history)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/lint',
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } },
  }

  # Binding under test: status.sha ∈ Repository(payload.repository).stacks.commits
  # vs actual: Commit.where(sha: status.sha) across ALL stacks
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  assert_not_equal 'success', victim_commit.status.state,
    "status from attacker/repo's webhook must not affect victim stack's commit"
end
```
This test demonstrates that `StatusHandler#process`'s `Commit.where(sha: params.sha)` (no stack/repo filter) causes the assertion to fail, proving the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
