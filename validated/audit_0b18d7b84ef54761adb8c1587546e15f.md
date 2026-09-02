### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup triggers `Stack#schedule_merges` for a victim stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits solely by `sha`, with no check that the commit's owning `Stack`/`Repository` matches the repository that authenticated the incoming webhook via `verify_signature`. Because `sha` is only unique per `(sha, stack_id)` pair (not globally), a `status` webhook that is validly signed for a repository the attacker controls can apply a forged `state: success` status to an identical-sha commit that belongs to an entirely unrelated victim stack, driving `Commit#add_status` to call `stack.schedule_merges` for the victim.

### Finding Description
The broken binding is: `authenticated_repository_owner(webhook) == commit.stack.repository.owner` (the repo whose signature was verified must equal the repo owning the mutated commit). This is never enforced.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from the webhook payload (`params.dig('repository','owner','login')`) and validates the HMAC using `Shipit.github(organization: repository_owner)`'s `webhook_secret` (`app/controllers/shipit/webhooks_controller.rb:24-49`, `59-62`). This only proves the request was signed by *some* org's configured secret - the org named in the very same attacker-controlled payload.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
(`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`). This query is global across all stacks/repositories - it has no `stack_id` or repository filter tying the lookup back to the repository that was actually verified.
- The DB schema confirms this is exploitable: the unique index on `commits` is `(sha, stack_id)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb:1-5`), not a unique index on `sha` alone - i.e., the schema explicitly allows the same `sha` to exist under multiple different stacks (as happens with forks/mirrors tracked as separate stacks).
- `commit.create_status_from_github!` → `add_status { statuses.replicate_from_github!(stack_id, github_status) }` creates the status under the commit's own `stack_id` (`app/models/shipit/commit.rb:165-169`, `366-386`) with no re-check of repository origin, and if the simple_state transitions (e.g. pending/unknown → success), `stack.schedule_merges if new_status.pending? || new_status.success?` fires for that commit's real stack (`app/models/shipit/commit.rb:379-384`).

Exploit flow: an attacker who owns/controls a repository that the same multi-tenant Shipit instance also tracks (and therefore has a legitimately configured `webhook_secret` for their own org) can push an identical commit (same tree/parents/author/committer timestamps/message - git SHA1 is content-addressed and repository-independent) to their own repo so that it hashes to the same `sha` as a commit already queued in the victim's `MergeQueue`. The attacker then triggers (or directly POSTs, since GitHub lets any repo owner fire/replay a `status` event for their own repo) a `status` webhook for their own repo with `state: success` and that colliding `sha`. `verify_signature` passes because it validates against the attacker's own org's secret, not the victim's. `StatusHandler#process` then finds and mutates the victim's `Commit`, and `stack.schedule_merges` runs for the victim stack using attacker-supplied, unauthenticated-for-that-repo data.

Existing guards do not close this gap: `verify_signature` only proves *an* org authenticated the payload, not that it's *the* org owning the target commit; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape of `sha`/`state`, not ownership; there is no `require_permission!`/`stacks` scope check anywhere in this webhook pipeline.

### Impact Explanation
A payload authenticated for one repository can mutate a `Commit`/trigger `Stack#schedule_merges` (and, per the existing `add_status` webhook-transition tests, also `deployable_status`/continuous-deployment hooks) belonging to a completely different repository/stack that never authenticated the request. This matches "a payload for one repository mutating another's stack, commit, task, or team" and can produce "an unauthorized deploy, rollback or merge" if the victim's merge queue only awaits this last green status - Critical severity. The blast radius spans every stack tracked by the same Shipit instance whose commit history can be made to intersect (via SHA collision through identical content) with a repository the attacker controls, which is realistic for forked/mirrored/vendored codebases sharing commit history across orgs.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment tracking more than one org/repo, each with its own legitimately configured `webhook_secret`; (2) attacker owns or administers at least one tracked repository (low bar - many Shipit deployments track many teams' repos with self-service onboarding); (3) attacker can produce a commit with byte-identical tree/parents/timestamps/message as the victim's queued commit, which is achievable when histories are shared (forks, vendoring, cherry-picks, mirrors) since git SHA1 is purely content-derived; (4) victim's merge queue configured to auto-merge purely on status success. This is a real, reachable path with attacker cost limited to controlling one tracked repo and reproducing commit content - not merely theoretical.

### Recommendation
Scope the `StatusHandler` (and analogous `CheckRunHandler`) commit lookup to the repository identified in the webhook payload, not merely by `sha`, e.g.:
```ruby
def process
  Commit.joins(stack: :repository)
        .where(sha: params.sha, shipit_repositories: { owner: repository_owner, name: repository_name })
        .each { |commit| commit.create_status_from_github!(params) }
end
```
so a status only ever applies to commits whose owning repository matches the one that was actually signature-verified for this request.

### Proof of Concept
Add to `test/models/webhooks/handlers/status_handler_test.rb` (or a new controller test under `test/controllers/webhooks_controller_test.rb`):

```ruby
test "status webhook for repo A must not mutate a commit belonging to repo B's stack" do
  victim_stack = shipit_stacks(:shipit) # repository X
  attacker_repo_owned_commit_sha = "deadbeef" * 5

  victim_commit = victim_stack.commits.create!(sha: attacker_repo_owned_commit_sha, author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "victim queued commit")

  # attacker's own stack/repo tracks an identical-sha commit
  attacker_stack = Shipit::Stack.create!(repository: Shipit::Repository.create!(owner: "attacker", name: "attacker-repo"), environment: "production", branch: "master")
  attacker_stack.commits.create!(sha: attacker_repo_owned_commit_sha, author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "attacker owned commit")

  Shipit::Stack.any_instance.expects(:schedule_merges).never rescue nil # baseline: only victim_stack should ever be asked

  payload = {
    'sha' => attacker_repo_owned_commit_sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'attacker' }, 'full_name' => 'attacker/attacker-repo' }
  }

  handler = Shipit::Webhooks::Handlers::StatusHandler.new
  handler.call(payload)

  # ASSERT the broken binding: victim commit MUST NOT receive a status from an
  # event authenticated only for the attacker's repository.
  assert_equal 0, victim_commit.reload.statuses.count,
    "status webhook signed for attacker/attacker-repo must not create a status on #{victim_stack.repository.full_name}'s commit"
end
```
This asserts the equality `authenticated_repository_owner == commit.stack.repository.owner` holds before any status/merge scheduling is applied; with the current unscoped `Commit.where(sha:)` lookup, the assertion fails because the victim's commit does receive the forged status and `stack.schedule_merges` is invoked for `victim_stack`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
