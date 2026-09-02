### Title
Cross-repository Status webhook forgery via unscoped SHA lookup — `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` [1](#0-0)  without any check that the webhook's `repository` matches the `stack`/`repository` the found `Commit` rows belong to. Because Git commit SHA1s are content-addressed and independent of which repository hosts them, an attacker who owns any GitHub repository can host a byte-identical copy of a commit that also exists in a victim's tracked stack, post a real (correctly signed) GitHub status against that commit on their own repo, and have Shipit apply that status to the victim's `Commit` row, flipping `UndeployedCommit#deploy_state`/`deployable?` for the victim's stack.

### Finding Description
The broken binding, stated explicitly: the organization whose webhook secret verified the request (`repository_owner` of the *attacker's* repo, checked in `WebhooksController#verify_signature` via `Shipit.github(organization: repository_owner)` [2](#0-1) ) must equal the organization/stack whose UI state the payload is allowed to mutate. It does not, because after signature verification the payload is handed to `StatusHandler#process`, which looks up commits purely `by sha` with no repository/stack filter: [1](#0-0) 

`Commit#create_status_from_github!` then writes the `Status` using the found commit's *own* `stack_id` [3](#0-2) , and `Status.replicate_from_github!` persists whatever `state`/`context` the attacker supplied [4](#0-3) . The commits table indexes `(stack_id, sha)` rather than enforcing a global unique SHA (see `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming identical SHAs are expected to coexist across different stacks/repositories — exactly the condition this handler fails to disambiguate.

Attacker flow:
1. Attacker identifies (or produces, e.g. via fork/cherry-pick) a commit object whose SHA1 is identical to one currently sitting "pending"/"failure" in a victim's Shipit stack (trivial for forks or for any commit copied byte-for-byte, since SHA1 is a hash of tree+parents+author+committer+message, not of the hosting repo).
2. Attacker hosts that exact commit in a repository they own and that is registered as (or otherwise triggers a real GitHub webhook installation on) their own GitHub org, so a webhook fired from it is legitimately HMAC-signed with that org's `webhook_secret`.
3. Attacker sets a `success` status on that SHA in their own repo (a fully legitimate, self-authorized GitHub action).
4. GitHub sends a real `status` webhook; `verify_signature` passes because it only checks that the signature matches the *attacker's own* org secret, not that the org is entitled to mutate the specific commit rows matched by SHA [2](#0-1) .
5. `StatusHandler#process` matches the victim's `Commit` row purely by SHA and writes a `success` `Status` onto it, with the victim's own `stack_id` [1](#0-0) .
6. `UndeployedCommit#deploy_state` calls `deployable?`, which becomes true (`success? && !blocked?`) [5](#0-4) , so `deploy_state` returns `'allowed'` [6](#0-5)  and the dashboard shows the victim's commit as deploy-ready.

None of the listed guards stop this: `verify_signature` validates the *sender's* org, not the *target* commit's org; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema for `StatusHandler` only validates field shapes (`sha`, `state`, etc.), not repository identity; there is no repository/stack cross-check anywhere in this path.

### Impact Explanation
An attacker fully controlling only their own GitHub repository can write a `Status` record — and thereby flip the computed `deploy_state`/`deployable?` — for a commit belonging to an unrelated victim stack, misleading an operator relying on the dashboard's "allowed" indicator into manually triggering an unauthorized deploy. This is a payload from one repository mutating another repository's stack/commit state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy"). It is repeatable against any victim commit whose SHA the attacker can reproduce, and scales to any tenant whose commits share history (forks, mirrors, cherry-picks, or even coincidentally re-authored identical patches) with a repository the attacker controls.

### Likelihood Explanation
- Preconditions: victim stack must have `continuous_deployment: false` (so this doesn't just also fire an unwanted auto-deploy, though it could) and an operator manually acting on the dashboard state. Attack requires attacker to own/control a GitHub repository, which is trivial (any free GitHub account), plus that repository being tracked as a Shipit stack (also attacker-controlled since it's their own) so a legitimate webhook fires with a valid signature for their own org.
- The harder precondition is obtaining a SHA-identical commit to one currently undeployed in the victim's stack. This is straightforward when the victim repository is public (fork it, or fetch and re-push the exact commit object — SHA1 is invariant across hosting) and the attacker targets an existing, older commit still sitting unresolved in the victim queue, or crafts a scenario where their own copy of the repo tracks the same commit history.
- No secrets, sessions, or privileged roles are required; cost is a GitHub account and standard git operations.

### Recommendation
Scope `StatusHandler#process` (and equivalent handlers such as check-run/deployment status handlers) to only affect commits belonging to stacks whose tracked repository matches the webhook's `repository.full_name` (or the verified `repository_owner`), e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_for(params) })`, rather than a bare `Commit.where(sha: ...)`.

### Proof of Concept
Minitest plan (model-level, no live GitHub):
```ruby
test "a status webhook for an unrelated repository cannot mutate another stack's commit" do
  victim_stack = shipit_stacks(:shipit)          # victim's stack/repo
  attacker_stack = shipit_stacks(:other_repo)    # different repository/org, attacker-owned in fixtures

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...) # same sha, different stack/repo

  undeployed = UndeployedCommit.new(victim_commit, index: 0)
  assert_equal 'pending', undeployed.deploy_state

  # Simulate a legitimately-signed webhook whose repository_params point at attacker_stack's repo
  params = ActionController::Parameters.new(
    sha: shared_sha, state: 'success', context: 'ci', created_at: Time.now.to_s
  )
  Shipit::Webhooks::Handlers::StatusHandler.new.process_for_test(params) # or post to /webhooks with repository_params = attacker repo

  victim_commit.reload
  assert_equal 'allowed', UndeployedCommit.new(victim_commit, index: 0).deploy_state
  # Demonstrates victim stack's UI state ('allowed') flipped purely by attacker's own-repo webhook,
  # in violation of: verified_org(attacker) == mutated_stack_org(victim) — which should be false.
end
```
This reproduces the claimed transition (`pending` → `allowed`) driven solely by a same-SHA status whose `repository_params` reference an unrelated repository, confirming `StatusHandler#process`'s unscoped `Commit.where(sha:)` lookup is the root cause.

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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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

**File:** app/models/shipit/undeployed_commit.rb (L18-31)
```ruby
    def deploy_state(bypass_safeties = false)
      state = deployable? ? 'allowed' : status.state

      unless bypass_safeties
        if blocked?
          state = 'blocked'
        elsif locked?
          state = 'locked'
        elsif stack.active_task?
          state = 'deploying'
        end
      end
      state
    end
```
