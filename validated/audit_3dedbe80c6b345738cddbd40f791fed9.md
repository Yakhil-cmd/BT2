### Title
Cross-repository `status` webhook forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository or organization scoping, then writes the attacker-supplied `state`/`context` to every matching commit record across all stacks in the installation. Because git SHAs are content-addressed and portable across repositories, an attacker who owns/controls any repository wired into the same Shipit installation can reproduce a victim commit's exact SHA and push a genuinely-signed `deploy/production` `success` status that gets applied to the victim stack's commit, potentially triggering `bot_login`-driven auto-deploy.

### Finding Description
The broken binding: `status.repository_owner` (the org that authenticated the webhook signature) should equal `commit.stack.repository.owner`/`full_name` for every `Commit` mutated by the handler. Instead: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` iterates **every** `Commit` row across **every** stack that happens to share that SHA — there is no `stack_id`/`repository` filter. The DB index is `index_commits_on_stack_id_and_sha`, confirming `sha` is only unique *per stack*, not globally, i.e. the schema itself assumes multiple, unrelated stacks can hold rows with the same SHA [2](#0-1) .

`create_status_from_github!` unconditionally records the pushed state via `add_status`, which — on a state transition to `success` — calls `stack.schedule_merges` and, if the stack has `continuous_deployment?` enabled, schedules `ContinuousDeliveryJob` for auto-deploy: [3](#0-2) [4](#0-3) [5](#0-4) 

Signature verification in `WebhooksController#verify_signature` only proves the payload came from GitHub for the **organization named in the payload's `repository.owner.login`** — it says nothing about which specific commit/stack the SHA belongs to: [6](#0-5) [7](#0-6) 

Exploit flow: the attacker forks or otherwise obtains push access to a repository within an organization that has Shipit's GitHub App/webhook installed (a repository they "own" per the threat model). They reproduce a commit object byte-for-byte identical to one already present in the victim's tracked repository (same tree, parent, author/committer identity and timestamps, message) — trivial since git objects are portable and content-addressed — giving an identical SHA. GitHub (or the attacker directly, since they control CI/status posting for their own repo) emits a legitimately-signed `status` event with `context: deploy/production`, `state: success` for that SHA. `WebhooksController#verify_signature` accepts it because the signature is valid for the attacker's own org. `StatusHandler#process` then finds the victim stack's `Commit` row with the same SHA (no scoping) and flips its status to success, satisfying the victim stack's required `deploy/production` context. If the victim stack has `bot_login` configured (`Shipit.user`) and continuous deployment enabled, this triggers an auto-deploy that runs and ships/rolls back as the bot identity, entirely outside the victim organization's control.

None of the existing guards prevent this: `verify_signature` only checks organization-level HMAC, not SHA-to-repo ownership; `drop_unhandled_event` only filters unknown event types; `ExplicitParameters` only validates payload shape (`sha`, `state`, `context` as strings); there is no `Repository`/`Stack` scoping anywhere in the `StatusHandler` or `Commit.where(sha:)` lookup.

### Impact Explanation
A successfully forged status flips deployability/merge-gating state (`deployable?`, `blocked?`, `schedule_merges`) for a commit belonging to a stack the attacker never authenticated against, and — when the victim stack runs continuous deployment with a `bot_login`-configured identity — can trigger an actual deploy/rollback executed under the bot's credentials. This is a payload from one repository mutating another's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). The attack is repeatable against any stack in the installation whose commit history intersects (by content-identical SHA) with a repository the attacker can push to or trigger CI on.

### Likelihood Explanation
Preconditions: (1) attacker needs write/CI-trigger access to some repository already integrated with the same Shipit instance (a low bar per the threat model — "push to a fork," "repository they own"); (2) a target commit SHA must be reproducible byte-for-byte in the attacker's repository, which is straightforward for any commit whose contents (tree, parents, author/committer metadata, message, timestamps) the attacker can inspect (e.g. public/open-source victim repos, or shared upstream history); (3) victim stack must require `deploy/production` and have `bot_login` + continuous deployment configured to convert the flip into an actual auto-deploy. Given SHA collision here is not cryptographic forgery but exact content replication (always possible when the commit content is visible), and the query has zero scoping, this is straightforward and repeatable.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` by the repository that authenticated the webhook (e.g., join through `stack.repository` matching `params.dig('repository','full_name')`/`repository_owner`, or restrict to `Commit.where(sha: params.sha, stack_id: Stack.where(repository: matching_repo).select(:id))`) instead of a bare, cross-tenant `Commit.where(sha:)`.

### Proof of Concept
minitest plan (models/webhooks test, no live GitHub):
1. Create two stacks, `stack_a` (attacker's repo, e.g. `attacker/repo`) and `stack_b` (victim, e.g. `victim/repo`, with `bot_login` set to a `Shipit.user` bot and `continuous_deployment?` true, requiring `deploy/production`).
2. Create `Commit` rows with the **same** `sha: "deadbeef..."` for both `stack_a` and `stack_b` (simulating content-identical commits in different repositories).
3. Assert baseline: `stack_b.commits.find_by(sha: sha).deployable?` is `false` (no `deploy/production` status yet) — LHS/RHS of invariant: `commit_b.status(deploy/production) == unknown`, `commit_b.stack.repository.full_name == 'victim/repo'`.
4. Instantiate `StatusHandler` with `params = { sha: sha, state: 'success', context: 'deploy/production' }` as if it came from a webhook signed for `attacker/repo`'s organization, and call `.process`.
5. Assert `stack_b.commits.find_by(sha: sha).reload.deployable?` is now `true` (or `status.success?` true) — proving a status "authenticated" only for `attacker/repo` altered `stack_b`'s (victim's, unrelated repository's) commit state, violating "a `deploy/production` status affects only the repository that authenticated it."
6. Optionally assert `ContinuousDeliveryJob` was enqueued for `stack_b` as a result, demonstrating the auto-deploy trigger under the bot identity.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-20)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/models/shipit/commit.rb (L279-287)
```ruby
    end

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
