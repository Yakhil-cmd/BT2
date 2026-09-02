### Title
`StatusHandler#process` applies incoming GitHub `status` webhooks to every `Commit` sharing a SHA across all stacks, regardless of which repository sent the webhook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no scoping to the repository that authenticated the webhook, unlike every other handler (`PushHandler`, `CheckSuiteHandler`, the `PullRequest` handlers) which all restrict to `stacks` derived from `payload.dig('repository', 'full_name')`. Because `Commit` rows are shared-key on `sha` (unique only per `(sha, stack_id)`), a webhook that GitHub legitimately signs for repository A can create a `Status` for a `Commit` belonging to a completely different tenant's `Stack` B, as long as both stacks happen to contain a `Commit` row with the identical SHA.

### Finding Description
The claimed-safe binding is: `repository_that_authenticated_payload.full_name == stack_that_receives_status_update.repository.full_name`. This binding is enforced in every other handler via `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks` [1](#0-0) , and is honored by `PushHandler#process` (`stacks.not_archived.where(branch:)`) [2](#0-1)  and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`) [3](#0-2) .

`StatusHandler#process`, however, never calls `stacks` and instead queries the global `Commit` table by SHA alone: [4](#0-3) 
This means the binding is broken: after the write, `commit.stack.repository.full_name` for the record actually mutated can differ from `payload.dig('repository','full_name')` that the signature verified. `verify_signature` only proves the payload came from a known GitHub organization for the `repository_owner` in the payload [5](#0-4) ; it says nothing about which `Commit`/`Stack` rows the handler is allowed to touch, and `StatusHandler` does not add that check itself.

Exploit flow: an attacker who owns/controls a repository whose organization is already known to Shipit (per the stated threat model, they can "emit webhooks from a repository they own") reproduces a commit object (same tree, parents, author, committer, timestamps, message) that is identical - and therefore has an identical SHA1 - to a commit sitting at `next_commit_to_deploy` in a victim's continuous-deployment-enabled `Stack` (e.g., because the victim repo is public, or the attacker forked it and both share history). The attacker then triggers a genuine, correctly signed GitHub `status` event for that SHA on their own repository (e.g., via their own CI setting a commit status). `StatusHandler#process` fires for every `Commit` row with that SHA in the entire installation, including the victim's, and calls `commit.create_status_from_github!(params)` → `statuses.replicate_from_github!(stack_id, github_status)` using the *victim's* `stack_id` [6](#0-5) [7](#0-6) . If `params.state == 'success'`, this flips `commit.success?` to true, so `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) can become true [8](#0-7) . `Status#schedule_continuous_delivery` runs `after_commit` on create [9](#0-8) [10](#0-9) , enqueuing `ContinuousDeliveryJob`, which calls `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` → `trigger_deploy` [11](#0-10) , causing a real deploy of the victim stack triggered by a webhook that never authenticated for that repository.

None of the listed guards prevent this: `verify_signature` validates GitHub's HMAC for the payload's own organization, not cross-stack access; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler` only validates shape (`sha`, `state`, etc.), not repository ownership; there is no `require_permission!`/`stacks` scoping call in this handler as there is in the others.

### Impact Explanation
A `status` webhook honestly signed for repository A causes a `Status` record to be written for a `Commit` belonging to `Stack` B (a different tenant/repository), and — when B has `continuous_deployment: true` and the colliding commit is `next_commit_to_deploy` — triggers an actual deploy (`Deploy` creation, `PerformTaskJob`/`ContinuousDeliveryJob` execution) on B's deploy host using B's `GITHUB_TOKEN`/deploy credentials, without any authentication tied to B. This is a cross-tenant write and an unauthorized-deploy trigger, matching the "Critical: payload for one repository mutating another's stack/commit/task ... or an unauthorized deploy" category. It is repeatable against any stack sharing a colliding SHA with a repository the attacker controls.

### Likelihood Explanation
Preconditions: (1) victim `Stack` has `continuous_deployment: true`; (2) the colliding SHA is (or becomes) `next_commit_to_deploy`; (3) the attacker's own repository/organization is already recognized by Shipit's webhook signature verification (`Shipit.github(organization: repository_owner)` must resolve, otherwise `GithubOrganizationUnknown` returns 422); (4) the attacker can produce (not merely guess) an identical commit object, which is realistic when history is shared (forks, cherry-picks with identical metadata, subtree merges) rather than requiring an actual SHA1 collision. Given these are plausible in multi-repo/multi-org Shipit deployments where the attacker legitimately owns a tracked repository, the attack is feasible and cheap once the shared-SHA condition is met, and is repeatable against any stack with a matching commit.

### Recommendation
Scope `StatusHandler#process` the same way as the other handlers: use `stacks` (derived from `payload.dig('repository','full_name')`) to restrict the commits updated, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`, so a status can only be applied to commits belonging to stacks whose repository actually matches the authenticated payload's repository.

### Proof of Concept
Minitest plan (model/controller level, no live GitHub):
1. Create two stacks, `victim_stack` (with `continuous_deployment: true`, repository `victim/repo`) and `attacker_stack` (repository `attacker/repo`).
2. Create `Commit` rows with the identical `sha` `"deadbeef..."` under both `victim_stack.id` and `attacker_stack.id`, with the victim commit being `victim_stack.next_commit_to_deploy` candidate (no prior deploy blocking it).
3. Stub `GithubHook`/`verify_signature` as in `test/controllers/webhooks_controller_test.rb` to simulate a legitimately signed webhook for `attacker/repo`.
4. POST to `/webhooks` with `X-Github-Event: status`, body `{ sha: <shared_sha>, state: 'success', repository: { full_name: 'attacker/repo', owner: { login: 'attacker' } } }`.
5. Assert `victim_stack.commits.find_by(sha: shared_sha).success?` becomes true, `assert_difference('Deploy.count', 1)` and `assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack])`, proving a webhook authenticated only for `attacker/repo` mutated and deployed `victim_stack`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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
