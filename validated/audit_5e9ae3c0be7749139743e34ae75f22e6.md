### Title
Cross-tenant `ContinuousDeliveryJob` enqueue via unscoped sha lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire database (`Commit.where(sha: params.sha)`), without restricting to the stacks that belong to the repository that authenticated the webhook. Since `Status#schedule_continuous_delivery` fires unconditionally on any created `Status`, an attacker who can get a validly-signed `status` webhook delivered for their own low-trust org can enqueue `ContinuousDeliveryJob` against any other tenant's stack whose commit table happens to contain a matching sha.

### Finding Description
The broken binding is: `commit.stack` (the stack Shipit acts on) `==` `Repository.from_github_repo_name(payload.dig('repository','full_name')).stacks` (the stack that actually authenticated the webhook via `verify_signature`). These are not equal.

`WebhooksController#verify_signature` only proves that the payload's HMAC matches the GitHub App secret for `repository_owner` (`params.dig('repository','owner','login')`) [1](#0-0) . It does not constrain which Shipit records the handler is allowed to touch — that is left to each handler.

The `Handler` base class exposes exactly the scoping primitive needed for this: `stacks` resolves only the stacks belonging to `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [2](#0-1) . `StatusHandler#process`, however, ignores this and queries commits globally:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

`create_status_from_github!` creates a `Status` row tied to `commit.stack` [4](#0-3) . `Status` has `after_commit :schedule_continuous_delivery, on: :create` which unconditionally calls `commit.schedule_continuous_delivery` [5](#0-4) , and that in turn enqueues the job whenever the victim stack is deployable and has continuous deployment enabled:
```
def schedule_continuous_delivery
  return unless deployable? && stack.continuous_deployment? && stack.deployable?
  ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
end
``` [6](#0-5) 

Exploit flow: the attacker controls a repository/org that is onboarded to the same Shipit instance (a low-trust tenant, e.g. their own fork/org with a Shipit stack). They cause GitHub to send a `status` event (e.g. by pushing a commit and having any CI/integration post a commit status, or via GitHub Apps/Actions on their own repo) for a commit sha that is identical to a commit sha existing in the victim's stack (git commit hashes are content-addressed — the same upstream commit imported/cherry-picked/rebased into two different repos yields the same sha; this is common with shared open-source dependencies, submodules, or forked upstream history). GitHub signs this webhook with the attacker's own org's legitimate app secret, so `verify_signature` passes for the attacker's own org. `StatusHandler#process` then matches every `Commit` row across all tenants with that sha — including the victim's — and creates a `Status` on it, triggering `ContinuousDeliveryJob.perform_later(victim_stack)` if the victim stack is unlocked and has `continuous_deployment` enabled.

Existing guards do not stop this: `verify_signature` validates only that the *sender* org is genuine, not that the *target records* belong to that org [7](#0-6) ; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema in `StatusHandler` validates field types/presence but has no repository-ownership check [8](#0-7) ; and the `Handler#stacks`/`repository_name` scoping helper exists but is simply not invoked by this handler.

### Impact Explanation
A `Status` record is written for, and a background job (`ContinuousDeliveryJob`) is enqueued against, a stack belonging to a completely different tenant than the one that authenticated the webhook — this is exactly the "payload for one repository mutating another's stack/commit/task" Critical category. If the victim stack has continuous deployment enabled, this can trigger an actual unauthorized deploy attempt on the victim's infrastructure (via `ContinuousDeliveryJob` → `Deploy`), purely from a sha collision the attacker can engineer deterministically by importing shared history. This is repeatable against any stack whose commit table contains a sha also present in a repo the attacker controls, and the blast radius spans all tenants sharing the Shipit instance.

### Likelihood Explanation
Preconditions: attacker needs a repository/org onboarded to the Shipit instance (so `verify_signature` succeeds for their org) and must find/produce a sha collision with a victim commit — trivially achievable via shared upstream history, forked repos, or cherry-picked/rebased commits (git shas are deterministic over content+metadata, not repository). No Shipit session, API token, or GitHub secret is required from the attacker; GitHub itself signs the webhook. Given a shared open-source/multi-tenant Shipit deployment (which is the intended use case per `Repository.from_github_repo_name`), this is realistically and repeatably exploitable at low cost.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to stacks owned by the repository named in the webhook payload, mirroring the `Handler#stacks` helper, e.g. restrict the query to `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or add a `stack_id: stacks.ids` condition to the `Commit.where` lookup, so a webhook can only ever affect commits/stacks tied to the authenticated repository.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status from an unrelated repository must not enqueue ContinuousDeliveryJob for a foreign stack" do
  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  victim_stack = shipit_stacks(:shipit) # some other tenant's stack
  victim_stack.update!(continuous_deployment: true, lock_reason: nil)
  victim_commit = victim_stack.commits.last

  # Attacker's own repository, but a status payload whose sha collides
  # with victim_commit.sha and whose repository.full_name is NOT
  # victim_stack's repository.
  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  assert_no_enqueued_jobs only: ContinuousDeliveryJob do
    post :create, body:, as: :json
  end
end
```
This test currently fails (the job IS enqueued for `victim_stack`), proving `Commit.where(sha: params.sha)` in `app/models/shipit/webhooks/handlers/status_handler.rb` is unscoped to the authenticated repository.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
