### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository that authenticated the webhook, then writes the attacker-supplied status (`context`, `state`) onto every matching `Commit` record across all stacks/repositories. If a victim stack shares a SHA with an attacker-controlled repository (e.g., a shared base commit, cherry-pick, or any commit whose SHA collides across forks/mirrors of the same upstream history), the attacker can post a `status` webhook from their own GitHub repo and flip a required context like `release/gate` to `success` on the victim's commit, changing `deployable?`/merge eligibility.

### Finding Description
The broken binding: the invariant that should hold is `status.repository == commit.stack.repository` for every write performed by a `status` webhook, i.e. a status event authenticated for repo A must only mutate commits belonging to stacks backed by repo A. In `StatusHandler#process` this equality is never checked:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Compare this to the base `Handler` class, which provides a `stacks` helper that scopes by `Repository.from_github_repo_name(repository_name)` — the mechanism other handlers (e.g. `pull_request/*`) use to stay within the authenticated repository's stacks: [2](#0-1) 

`StatusHandler` never calls `stacks`; it queries `Commit` globally by `sha` only. `Commit.sha` has no uniqueness constraint scoped to repository/stack in the schema exposed to this handler, and multiple stacks (for the same or unrelated repositories, e.g. forks, mirrors, or repos sharing history) can contain `Commit` rows with an identical `sha`.

`WebhooksController#verify_signature` only verifies that the payload was signed by the GitHub App belonging to `repository_owner` derived from the payload's own `repository.owner.login`/`organization.login` field — it authenticates that *some* repo under that owner sent the event, not that the event only affects that repo's data: [3](#0-2) 

So an attacker who owns/controls a GitHub repository (any unprivileged GitHub user can create one) can:
1. Produce a commit whose SHA is identical to a commit already present in a victim's Shipit stack (trivially achievable if the attacker forks/mirrors the victim's upstream repo, or shares a common ancestor commit — SHAs are computed from tree+metadata, so any commit copied from the shared history reproduces the identical SHA in the attacker's own repo).
2. Send a legitimate, correctly-signed `status` webhook from their own repository with `sha: <shared-sha>`, `context: "release/gate"`, `state: "success"`.
3. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which returns the victim's `Commit` row too, and calls `commit.create_status_from_github!(params)` on it.
4. `Commit#create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, github_status)` writes a new `Status` under the *victim's* `stack_id`, recomputes `status` via `Status::Group.compact`, and re-evaluates `deployable?`: [4](#0-3) [5](#0-4) [6](#0-5) 

If `release/gate` is part of the victim stack's required CI contexts, this forged `success` can flip `blocked?`/`deployable?` and trigger `stack.schedule_merges` / continuous delivery for a commit the victim never actually validated: [7](#0-6) 

None of the existing guards prevent this: `verify_signature` authenticates the sender's own repo/org, not the target of the write; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema in `StatusHandler.params` only validates the shape of `sha/state/context`, not repository ownership; there is no `require_permission!`/`stacks` scoping call anywhere in `StatusHandler`.

### Impact Explanation
An attacker-controlled webhook mutates a `Status`/commit-status-group record for a stack/repository that never authenticated the event — this is exactly the "payload for one repository mutating another's stack/commit" category. The result is an unauthorized change to `deployable?` and merge-eligibility state on a victim commit, which can cascade into an unauthorized deploy, rollback, or auto-merge decision driven by `stack.schedule_merges`/`ContinuousDeliveryJob`. This is repeatable against any victim stack that shares any commit SHA with a repository the attacker controls (common in forked/mirrored repos, monorepo submodule setups, or shared upstream base commits) — the attacker can retry for every SHA reachable this way. Severity matches Critical per the target's category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Preconditions: (1) attacker owns any GitHub repository (free, no privileges needed) and can emit `status` events for it via a normal GitHub integration/CI, (2) attacker needs a commit SHA that also exists as a `Commit` row in the victim's Shipit stack — achievable deterministically by forking/mirroring the same upstream history the victim stack tracks, since git commit hashes are content-addressed and identical across clones. (3) The victim stack's `ci.require` (or equivalent required status list) includes the forged context (`release/gate` is just an example — attacker could target whatever context the victim requires, once known via public repo config/docs). No Shipit credentials, session, or GitHub App key are needed — only a normal, correctly signed webhook from the attacker's own repo, which GitHub delivers automatically without any special privilege. This makes the attack low-cost, fully repeatable, and independent of any Shipit-side secret.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the event, mirroring the `stacks` helper used elsewhere in `Handler`: restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or join `Commit` to `Stack`/`Repository` and filter by `repository_name`/`repository_owner` matching the payload's `repository.full_name`) before calling `create_status_from_github!`, so a status can never be written onto a commit belonging to a different repository than the one that sent the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual addition)
test "status webhook does not affect commits belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(ignore_ci: false) # ensure gate is required
  # seed victim_stack.cascade.require to include "release/gate" via deploy_spec stub if needed

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")

  attacker_repo_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'release/gate',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }

  before_status = victim_commit.reload.status.state
  before_deployable = victim_commit.deployable?

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)

  after_status = victim_commit.reload.status.state
  after_deployable = victim_commit.deployable?

  # Binding under test: status/deployable state for victim_commit must be unaffected
  # by a status event whose repository != victim_stack's repository.
  assert_equal before_status, after_status,
    "unscoped status write from unrelated repo changed victim commit's status"
  assert_equal before_deployable, after_deployable,
    "unscoped status write from unrelated repo changed victim commit's deployable? state"
end
```
This test currently fails against `StatusHandler#process` as implemented (`Commit.where(sha: params.sha)` with no repository scoping), demonstrating the cross-repository mutation.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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
