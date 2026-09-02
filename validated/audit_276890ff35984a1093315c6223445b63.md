### Title
`StatusHandler#process` creates a `Status` for any commit sharing a sha, without validating the webhook's `repository.full_name` against the commit's owning `stack.repository`, triggering unauthorized CD deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, with no check that `params.repository.full_name` matches `commit.stack.repository.full_name`. Since a newly-created `success` `Status` triggers `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob`, any webhook sender whose payload's `sha` collides with a commit tracked by a *different* stack can flip that unrelated stack's commit to `deployable?` and cause an unauthorized deploy.

### Finding Description
The binding that should hold is: `params.repository.full_name == commit.stack.repository.full_name` for every `commit` on which a `Status` is created from a webhook. Tracing the code:

- `app/models/shipit/webhooks/handlers/status_handler.rb` schema only requires `sha`, `state`, and a few optional fields — it never requires or validates `repository` in the `params do ... end` block: [1](#0-0) 
- `process` resolves target commits solely by sha, with no scoping to the sending repository: [2](#0-1) 
- `Commit#create_status_from_github!` → `Status.replicate_from_github!` persists the status against `stack_id` taken from the commit found, not from the payload: [3](#0-2) [4](#0-3) 
- Creating a `Status` fires `schedule_continuous_delivery`, which unconditionally calls `commit.schedule_continuous_delivery`: [5](#0-4) 
- `Commit#schedule_continuous_delivery` only checks `deployable? && stack.continuous_deployment? && stack.deployable?` — it never inspects which repository's webhook produced the triggering `Status`: [6](#0-5) 
- `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` builds and enqueues a real `Deploy` once these conditions hold, as shown in `stack_test.rb`'s coverage of `#trigger_continuous_delivery` triggering a deploy when conditions are met: [7](#0-6) 

The webhook signature check (`WebhooksController#verify_signature`) authenticates only that the request came from a valid GitHub App installation for `repository_owner`, i.e., that the sender legitimately owns/controls *some* repository whose events reach this endpoint: [8](#0-7) . It does not, and cannot, establish that the sha inside the payload belongs to the sender's own repository — that binding is expected to be enforced inside the handler, and `StatusHandler` never does this.

**Exploit flow:** An attacker who has any GitHub App/webhook integration installed on a repository they control (e.g., an app installed on many orgs with a shared or per-org, but not per-repo, secret verifiable against their own org) can set a `success` status on a commit sha in their own repo. If that sha also exists as a `Shipit::Commit` for an unrelated victim stack — which happens whenever a victim commit's sha is guessable/known (git shas are public and are routinely known by anyone who can see the victim's GitHub history, PRs, or the Shipit UI itself, since commit shas are not secrets) — the forged status webhook creates a `Status` row against the victim's `Commit`, flips `deployable?` to true, and (if the victim stack has CD enabled and is otherwise deployable) enqueues `ContinuousDeliveryJob`, producing an unauthorized `Deploy`.

### Impact Explanation
This allows a webhook sender to write a `Status` record for, and potentially trigger a deploy against, a stack/repository they do not own or authenticate for — matching the "Critical" category ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy"). The blast radius is any stack with `continuous_deployment: true` whose next candidate commit sha is known to the attacker (shas are inherently non-secret), across any tenant/org configured on the same Shipit instance, and is repeatable per known sha.

### Likelihood Explanation
Preconditions: the target stack must have `continuous_deployment` enabled and otherwise be `stack.deployable?` (not locked, not deploying-too-recently, has a valid deploy spec, etc. — same as stated in the question). The attacker needs a way to have a `status` webhook accepted by `verify_signature`, meaning they need a valid signature for *some* organization known to the Shipit instance's `Shipit.github` configuration; the code only verifies that the signature matches the org derived from `repository.owner.login` in the payload, not that this org is the one that owns the target commit. Because `repository` is never validated against the commit's stack, the actual exploit requirement is solely "attacker's signed payload's `sha` field collides with a `Commit.sha` belonging to a different stack" — commit shas are public, non-secret data, making this a low-cost, repeatable attack once the attacker's webhook can pass signature verification at all.

### Recommendation
In `StatusHandler#process`, require `repository.full_name` in the params schema and filter matched commits to only those whose `commit.stack.repository.full_name == params.repository.full_name` (or `commit.stack.repository_id == repository.id`) before calling `create_status_from_github!`. Apply the same repository-scoping check pattern used in other handlers like `ReopenedHandler`/`EditedHandler`, which resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and scope lookups through `joins(:stack, stack: :repository)`.

### Proof of Concept
Add to `test/models/commits_test.rb` (or a new webhook handler test) a minitest:
```ruby
test "status webhook for unrelated repository must not schedule CD for a colliding sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.create!(sha: "deadbeef", message: "victim commit", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  attacker_payload = OpenStruct.new(
    sha: victim_commit.sha,
    state: "success",
    description: nil, target_url: nil, context: "ci",
    repository: OpenStruct.new(full_name: "attacker/unrelated-repo")
  )

  assert_no_enqueued_jobs(only: Shipit::ContinuousDeliveryJob) do
    Shipit::Commit.where(sha: attacker_payload.sha).each { |c| c.create_status_from_github!(attacker_payload) }
  end

  refute_predicate victim_commit.reload, :deployable? # or assert no Deploy was created for victim_stack
end
```
Binding assertion before/after: `attacker_payload.repository.full_name` ("attacker/unrelated-repo") != `victim_stack.repository.full_name`, yet `victim_commit.create_status_from_github!` still succeeds and (in the current code) still calls `schedule_continuous_delivery`, demonstrating the missing check.

### Citations

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

**File:** app/models/shipit/stack.rb (L210-210)
```ruby
    def trigger_continuous_delivery
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
