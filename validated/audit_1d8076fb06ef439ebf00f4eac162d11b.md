### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status authenticated for one repository mutate CI state on another repository's commit/stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by bare SHA, with no filter on the repository/stack that authenticated the webhook, and then persists a `Status` scoped to that commit's own `stack_id`. Because forks/mirrors of the same upstream repository share identical commit SHAs, an attacker who legitimately controls a repository sharing history with a victim's tracked stack can flip CI state (`ci/kubernetes` or any other context) on the victim stack, including a production-environment stack, triggering continuous deployment or blocking deploys.

### Finding Description
The broken binding: the code assumes `commit.stack == repository_that_sent_the_webhook`, i.e. `Commit#stack_id == repository_owner(params)`. This is false — `Commit.where(sha: params.sha)` is entirely repository-agnostic.

Path:
- `WebhooksController#create` dispatches the parsed body to `Shipit::Webhooks.for_event('status')`, after `verify_signature` checks the HMAC using `Shipit.github(organization: repository_owner)` — this only proves the payload came from *some* legitimately signed event for that GitHub org/app, not that the named `sha` belongs to the repository that raised the event. [1](#0-0) 
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no `stack_id`/repository filter. [2](#0-1) 
- `create_status_from_github!` creates the `Status` scoped to `stack_id` — the **commit's own** stack, not the attacker's stack: `statuses.replicate_from_github!(stack_id, github_status)`. [3](#0-2) 
- `Status` creation fires `enable_ci_on_stack` and, on `after_commit`, `schedule_continuous_delivery`, which calls `commit.schedule_continuous_delivery` → `ContinuousDeliveryJob` if the stack is `continuous_deployment?` and `deployable?`. [4](#0-3) [5](#0-4) 

`Commit` rows are only indexed/looked-up by `(stack_id, sha)`, but the handler queries only by `sha`, spanning every stack in the install.


Exploit flow: an attacker forks (or otherwise shares commit history with) a repository that Shipit tracks as a victim stack with `environment: production`. Because git SHAs are content-addressed, the fork shares identical commit SHAs with the upstream history at fork time. The attacker sends (or triggers, via their own CI on their own fork) a real, validly-signed `status` webhook for their own repository/org, naming a `sha` that is shared with the victim stack and `context: ci/kubernetes` (or whatever context the victim stack's `deploy_spec` lists under `ci.require`/`ci.blocking`), with `state: success` or `state: failure` of their choosing. `verify_signature` passes because the signature is valid for the attacker's own org/app. `StatusHandler#process` then finds **all** `Commit` rows with that SHA — including the victim's — and writes a `Status` on the victim stack's commit, using attacker-chosen `state`. This can force a required CI context green (unblocking an unwanted deploy via continuous delivery) or force it red (blocking legitimate deploys on the production stack).

Existing guards fail to prevent this because `verify_signature` only authenticates *which organization/app* sent the payload, never *which repository's commits the payload is allowed to affect*; `ExplicitParameters` only validates field types/presence of `sha`, `state`, `context`, etc., not ownership; and there is no `stacks`/repository scope applied inside `StatusHandler#process`.

### Impact Explanation
An attacker who authenticates a webhook for their own (or a shared-history) repository can create `Status` rows attributed to another tenant's stack/commit — this is the explicit Critical category "a payload for one repository mutating another's stack, commit, task." If the victim stack has `continuous_deployment: true`, forcing a required context to `success` can trigger an unauthorized deploy of attacker-influenced commits (`ContinuousDeliveryJob`); forcing failure on a `production` stack blocks legitimate ships/rollbacks. The blast radius is any stack whose tracked repository shares commit history (a fork, mirror, or later re-attached repo) with a repository the attacker controls, and it is repeatable per shared SHA and per webhook.

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository (their own, or any account) that shares commit SHAs with a repository Shipit tracks as a stack (trivially satisfied by forking public repos, which is extremely common in the GitHub workflow Shipit is designed around), and that repository must be able to raise a real, GitHub-signed `status` webhook (any push with a CI integration, or the GitHub Status API with a personal token on their own repo, achieves this — no Shipit secrets needed). This requires no Shipit credentials, session, or API token — only ordinary GitHub repository ownership, matching the "unprivileged attacker" definition. Feasibility is high and the attack is fully repeatable against any stack sharing history with an attacker-controlled repo.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to commits belonging to stacks whose tracked repository matches `repository_owner`/`repository.full_name` from the webhook payload (e.g., `Commit.joins(:stack).merge(Stack.where(repository: matching_repo)).where(sha: params.sha)`), rather than a bare global `Commit.where(sha:)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two `Repository`/`Stack` records: `victim_stack` (`environment: 'production'`, `continuous_deployment: true`, deploy spec requiring `ci/kubernetes`) tracking `victim/repo`, and `attacker_stack` tracking `attacker/repo`.
2. Create `Commit` rows with the **same** `sha` (`shared_sha`) under both `victim_stack` and `attacker_stack` (simulating shared fork history).
3. Build `params` as `StatusHandler` params with `sha: shared_sha, context: 'ci/kubernetes', state: 'success'` (as would arrive from a webhook signed for `attacker/repo`).
4. Assert the equality that should hold but doesn't: before processing, `victim_stack.commits.find_by(sha: shared_sha).statuses.count == 0`; call `Shipit::Webhooks::Handlers::StatusHandler.call(params_hash)`; assert `victim_stack.commits.find_by(sha: shared_sha).statuses.where(context: 'ci/kubernetes').exists?` is now `true` even though the webhook was never authenticated for `victim/repo`.
5. Additionally assert `ContinuousDeliveryJob` is enqueued for `victim_stack` (or that `victim_stack.deployable?`/ship proceeds), demonstrating cross-repository mutation of production stack state from an attacker-controlled repository's webhook.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
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
