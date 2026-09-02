### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no repository scoping, unlike every other event handler in the codebase (e.g. the `pull_request/*` handlers, which resolve the target stack via `repository.full_name`). Because a git SHA is content-addressed and can exist identically in multiple repositories (forks, cherry-picks, shared history), a validly-signed `status` webhook from repository A can flip the CI status of a same-SHA commit belonging to an unrelated stack for repository B, potentially triggering `Commit#schedule_continuous_delivery` and an unauthorized deploy on B.

### Finding Description
The broken binding: the code should enforce `commit.stack.repository == payload.repository` before applying a status, but instead the actual code is: [1](#0-0) 

`Commit.where(sha: params.sha)` matches every `Commit` row across every `Stack`/repository in the installation that happens to share that SHA, and calls `commit.create_status_from_github!(params)` on each, which persists a new `Status` and can immediately trigger `Commit#schedule_continuous_delivery` -> `ContinuousDeliveryJob` for the owning stack: [2](#0-1) [3](#0-2) 

By contrast, the `pull_request/*` handlers resolve the target stack/repository from `payload.repository.full_name` before acting, showing the repository-scoping is the intended design that `StatusHandler` fails to implement.

Signature verification (`WebhooksController#verify_signature`) only proves the request came from the GitHub organization named in the payload's own `repository.owner.login`/`organization.login` — it authenticates *which org sent the webhook*, not *which commits the org is allowed to affect*: [4](#0-3) [5](#0-4) 

So an attacker who legitimately controls a repository integrated with the same multi-tenant Shipit instance (e.g. their own fork/repo registered as a Shipit stack — an ability explicitly granted to the "unprivileged attacker" in this exercise: "push to a fork ... emit webhooks from a repository they own") can have GitHub emit a real, correctly-signed `status` event for a commit SHA in their own repo. If that SHA also exists as a `Commit` row belonging to a *different* stack/repository (common when repos share history via forking, subtree merges, or cherry-picks that preserve the exact same tree/parents/author/committer/timestamps), `StatusHandler#process` will apply the attacker-controlled `state: success` to the victim stack's commit too, since it never checks which repository produced the event. This directly breaks the stated invariant: "A GitHub status may only alter the CI state of commits in the repository that actually produced the status event."

### Impact Explanation
A single crafted (but validly-signed, from the attacker's own integrated repository) `status` webhook can flip CI state and `deployable?` for a commit belonging to a stack/repository the attacker does not own, and — if that stack has `continuous_deployment?` enabled — cause `Stack#trigger_continuous_delivery` to ship attacker-influenced state. This is a cross-tenant write: "a payload for one repository mutating another's stack, commit, task or team," matching the Critical impact category (unauthorized deploy). It is repeatable for any SHA collision the attacker can arrange and is not limited to a single victim stack — any stack sharing a colliding SHA is affected.

### Likelihood Explanation
Exploitation requires: (1) the attacker controls a repository that is a legitimately-configured Shipit stack in the same multi-tenant instance (satisfied by the stated attacker capabilities), and (2) a SHA collision between the attacker's repository and the victim's repository, which is realistic for forked repositories, shared subtrees, or cherry-picked commits with identical author/committer/timestamps/tree/parents — not requiring any cryptographic SHA-1 collision. No Shipit secrets, sessions, or elevated GitHub permissions are needed beyond what an ordinary repository owner already has for their own integrated repo.

### Recommendation
Scope `StatusHandler#process` (and ideally `Commit.where(sha:)` lookups generally) to the repository that produced the event, e.g. resolve the `Stack`/`Repository` via `params.dig('repository','full_name')` first, then constrain `Commit.where(sha: params.sha, stack: matching_stacks)` before calling `create_status_from_github!`, mirroring the repository-scoping already used by the `pull_request/*` handlers.

### Proof of Concept
minitest plan (no live GitHub required):
1. Create two `Repository`/`Stack` records for two different `full_name`s (e.g. `attacker/repo` and `victim/repo`), both with `continuous_deployment` enabled.
2. Create a `Commit` with the same `sha` (e.g. `"a" * 40`) under each stack, both currently pending/not deployable.
3. Build a `status` payload: `{ sha: <shared sha>, state: 'success', context: 'ci', repository: { full_name: 'attacker/repo', owner: { login: 'attacker' } } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)` (or run through the controller with signature verification stubbed to simulate the attacker's own valid signature).
5. Assert: `victim_commit.reload.status.success?` is `true` and `victim_commit.deployable?` is `true`, even though the payload's `repository.full_name` was `attacker/repo`, not `victim/repo` — demonstrating `commit.stack.repository == payload.repository` is violated (`false == false` expected, but the state changed as if `true`).
6. Optionally assert `ContinuousDeliveryJob` was enqueued for the victim stack via `assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [victim_stack])`.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
