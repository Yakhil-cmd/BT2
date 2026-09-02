### Title
`StatusHandler#process` matches commits by SHA across all stacks, letting a webhook from one repository forge CI status for another repository's commit and auto-trigger its continuous delivery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, without ever checking that the commit's `stack.repository` corresponds to the `repository` named in the incoming webhook payload. Because `sha` is only unique per `(sha, stack_id)` (not globally, see `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), a validly-signed `status` webhook from repository A can create a `Status` on a commit belonging to a completely unrelated stack tracking repository B, as long as both stacks happen to contain a `Commit` row with the same SHA (e.g. shared history through a fork, mirror, or cherry-pick).

### Finding Description
The broken binding: attacker claims `repository_owner(webhook A) == repository_owner(webhook A)` is what authorizes the write, but the code actually writes to `commit.stack` for **any** stack whose `commits` table contains a row with `sha == params.sha`, regardless of which repository the webhook's `payload['repository']['full_name']` names. So the true (broken) equality is:

`signed_repository(webhook) != repository(stack targeted by the resulting Status/schedule_continuous_delivery)`,

yet the code proceeds as if they were equal.

Code path:
- `app/controllers/shipit/webhooks_controller.rb#verify_signature` only checks that the HMAC signature is valid for the organization named in the payload (`repository_owner`) — it does not restrict which `Commit`/`Stack` rows the resulting handler may touch. [1](#0-0) 
- `StatusHandler#process` performs an unscoped, cross-repository lookup: [2](#0-1) 
- Contrast with `PushHandler#process`, which correctly scopes to `stacks` (derived from `Repository.from_github_repo_name(repository_name)` in the base `Handler` class) before acting: [3](#0-2) [4](#0-3) 
- The `Commit` table's uniqueness constraint is `(sha, stack_id)`, not `sha` alone, confirming the same SHA can legitimately exist in multiple stacks simultaneously: [5](#0-4) 
- Once `Status` is created for the victim commit, `after_commit :schedule_continuous_delivery` on `Status` fires unconditionally for the victim's stack: [6](#0-5) [7](#0-6) 
- `Stack#trigger_continuous_delivery` will then call `trigger_deploy`, which builds and enqueues a `Deploy` using the victim stack's own `cached_deploy_spec` and `env`, spawning a Task/Command with the victim's `GITHUB_TOKEN`: [8](#0-7) [9](#0-8) [10](#0-9) 

Attacker request: a `status` event POSTed to `/webhooks`, signed with the attacker's own org's `webhook_secret` (which they legitimately possess as the admin of their own GitHub App/org configured in Shipit), naming their own repository in `payload['repository']`, but with `sha` set to a value that also exists as a `Commit` row in the victim's stack (e.g. because the victim's repository was forked, mirrored, or shares a common ancestor commit with the attacker's repository — no SHA-1 collision attack is required, just overlapping git history, which is common for public repos/forks). Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate the attacker's own organization's signature; none of them check that the `Commit` rows being mutated belong to a stack whose `Repository` matches the webhook's `repository` field.

### Impact Explanation
An attacker who administers any GitHub org/repo integrated with the same Shipit instance (a routine, unprivileged tenant of a multi-tenant Shipit deployment) can create `Status` rows on, and potentially trigger an unauthorized deploy/rollback for, any other stack's commit that shares a SHA with a commit in the attacker's own repository. This is a payload for one repository mutating another repository's commit/stack state and, when `continuous_deployment: true`, can cause an unauthorized deploy that executes a `Command`/`PTY.spawn` using the victim stack's `GITHUB_TOKEN` and deploy environment — matching the "Critical" categories of "payload for one repository mutating another's stack/commit/task" and "unauthorized deploy." This is repeatable against any stack whose commit history overlaps with an attacker-controlled repository (forks are the common case), and scales across all such stacks on the shared Shipit instance.

### Likelihood Explanation
Preconditions: (1) attacker administers a GitHub org/repo already configured as a Shipit tenant (has a valid `webhook_secret` for their own org — not the victim's), (2) the victim stack has `continuous_deployment: true`, no active task, and is otherwise `deployable?`, (3) a `Commit` row with an identical SHA exists in both the attacker's and victim's stacks — most easily achieved when the victim repository is a fork/mirror of, or shares history with, the attacker's repository, or when the attacker forks the victim's public repo and both get separately synced into Shipit as distinct stacks. This requires no compromise of the victim's secrets and no SHA-1 preimage/collision attack — shared commit ancestry across forks is common and attacker-controllable (attacker can fork the victim's repo, wait for Shipit to sync it into its own stack, and then can freely emit `status` webhooks referencing any SHA from that shared history from their own signed context). This is realistically exploitable in typical multi-tenant/fork-heavy GitHub organizations.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing raw `Commit`/`Stack` lookups by SHA) to the repository named in the webhook payload, mirroring the `stacks` helper used by `PushHandler`. E.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a `status` event can only mutate commits belonging to stacks whose `Repository` matches the authenticated webhook's `repository.full_name`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` — for validation only, not part of shipped code):
1. Create two stacks, `victim_stack` (repository `victim/repo`, `continuous_deployment: true`, `cached_deploy_spec` present, no active task) and `attacker_stack` (repository `attacker/fork`).
2. Create a `Commit` with `sha: "deadbeef" * 5` under `attacker_stack` and an identical-SHA `Commit` under `victim_stack` (simulating shared fork history).
3. Build a `status` webhook payload with `repository.full_name == "attacker/fork"`, `sha` matching the shared SHA, `state: "success"`.
4. Assert the binding before: `attacker_payload["repository"]["full_name"] != victim_stack.repository.full_name`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert `victim_stack.commits.find_by(sha: shared_sha).statuses.exists?` is true (Status was written for a repo that never authenticated the webhook) — this is the violation.
7. Stub `Stack#trigger_deploy`/`Command.new`/`PTY.spawn` with Mocha `.expects` and assert it is invoked with `victim_stack`'s env (containing `victim_stack`'s `GITHUB_TOKEN`/repository) even though the triggering webhook's `repository` was `attacker/fork`, proving cross-tenant/cross-repository code execution using the victim's credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L19-19)
```ruby
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L54-63)
```ruby
    def env
      {
        'ENVIRONMENT' => environment,
        'LAST_DEPLOYED_SHA' => last_deployed_commit.sha,
        'GITHUB_REPO_OWNER' => repository.owner,
        'GITHUB_REPO_NAME' => repository.name,
        'DEPLOY_URL' => deploy_url,
        'BRANCH' => branch
      }
    end
```

**File:** app/models/shipit/stack.rb (L174-196)
```ruby
    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
          save!
        else
          Rails.logger.warning("#{changes.keys} field(s) were unexpectedly modified on stack #{id} while deploying")
        end
      end

      run_now = kwargs.delete(:run_now)
      deploy = with_lock do
        deploy = build_deploy(*args, **kwargs)
        deploy.save!
        deploy
      end
      run_now ? deploy.run_now! : deploy.enqueue
      continuous_delivery_resumed!
      deploy
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
