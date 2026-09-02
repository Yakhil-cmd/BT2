### Title
Cross-repository commit-status forgery in `StatusHandler#process` enables unauthorized deploy of another repo's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no scoping to the repository that sent the webhook, so a `status` event that passes signature verification for one repository/organization can mark a commit belonging to a completely different stack as `success`/deployable. Because webhook signature verification is performed at the organization (or global) level — never per-repository — this lets an attacker who controls any repo covered by the same webhook secret trigger `schedule_continuous_delivery` and an unauthorized deploy of a foreign stack.

### Finding Description
The broken binding is: **"repository that authenticated the webhook" == "repository that owns the commit being mutated"**. In this codebase that equality does not hold.

- `WebhooksController#verify_signature` resolves trust via `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight out of the attacker-influenced JSON body (`params.dig('repository','owner','login')`), and `Shipit#github` resolves to either a single global app config or an org-keyed config: [1](#0-0) [2](#0-1) 
- The webhook secret is per-organization at best (often a single global secret per `docs/setup.md`'s default single-app schema), **never per individual repository**. Passing `verify_signature` therefore only proves "this event came from GitHub for org X (or at all)", not "this event pertains to repository/stack Y".
- `StatusHandler#process` then does a completely unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no join/filter on `stack_id`, `repository`, or the payload's `repository.full_name`: [3](#0-2) 
- `create_status_from_github!` → `add_status` can transition the commit to `success`, which makes `Commit#deployable?` true (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`): [4](#0-3) [5](#0-4) 
- A newly-deployable commit calls `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob.perform_later(stack)` for **the commit's own stack**, not the stack tied to whichever repository actually sent the webhook: [6](#0-5) 
- `ContinuousDeliveryJob#perform` calls `stack.trigger_continuous_delivery`, which (if the stack is a continuous-deployment stack and deployable) builds and runs a real `Deploy`/`Command` using that stack's own `GITHUB_TOKEN`/environment: [7](#0-6) 

Exploit flow: attacker controls (or has push/API access to) a repository whose webhook events are routed to the same Shipit endpoint and validated with the same secret as the victim's org (this is the normal single-app/org-wide Shipit configuration described in `docs/setup.md`). The attacker learns the SHA of a commit belonging to a foreign, ephemeral review-stack (PR head SHAs are public). Using GitHub's Statuses API, which allows setting a status on an arbitrary SHA string from any repo the attacker has push access to, the attacker creates a `success` status referencing that foreign SHA. GitHub delivers a legitimately-signed `status` webhook (attacker's own repo, correctly HMAC'd with the org/global secret) to Shipit. `verify_signature` passes because it only checks the org-level secret, never which repository the SHA actually belongs to. `StatusHandler#process` then finds the victim's `Commit` row purely by SHA and applies the status, flipping the foreign stack's commit to deployable and enqueuing a real deploy job — all without the attacker ever having any relationship with, or credentials for, the victim repository/stack.

None of the listed guards close this gap: `verify_signature` authenticates the org/global secret, not the specific repository; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, etc.), not repository ownership; there is no `Repository`-format check or `stacks` scope applied inside `StatusHandler#process` at all.

### Impact Explanation
This is a cross-tenant integrity/authorization break: a request authenticated for repository/organization B causes a write (`Status` record + deployable transition) against repository A's `Commit`, and can trigger a real, unauthorized `ContinuousDeliveryJob` → `Command`/`PTY.spawn` deploy of stack A's code using stack A's `GITHUB_TOKEN` and deploy environment. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The attack is repeatable against any commit/stack sharing the same webhook secret scope (which, in the default single-app Shipit deployment, is effectively every repository configured in the installation), giving broad blast radius across all stacks hosted by one Shipit instance.

### Likelihood Explanation
Preconditions: (1) Shipit configured with the common single-app or single-org webhook schema (secret shared across all repos in scope — the documented default); (2) attacker has push/API access to any repository whose events reach this Shipit's webhook endpoint (e.g., any other repo in the same GitHub org, or their own repo if the GitHub App allows install-anywhere); (3) attacker can learn the target commit SHA (trivially public for PR-based review stacks). No Shipit credentials, sessions, or the actual `webhook_secret` value are required — only genuine GitHub-side status-setting rights on an unrelated repo. This is low-cost and fully repeatable.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stack(s) whose configured `repository` matches the webhook's `repository.full_name`/`repository.owner.login`, e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository: repo_full_name })`, and reject/ignore statuses whose payload repository does not match the commit's own stack repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status from an unrelated repository must not mark a foreign stack's commit deployable" do
  victim_stack = shipit_stacks(:review_stack) # repository: "victim/app"
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef', ...)
  victim_stack.update!(continuous_deployment: true)

  attacker_payload = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: victim_commit.sha, state: 'success',
    context: 'ci/attacker', description: nil, target_url: nil,
    created_at: Time.now.to_s, branches: []
  )
  # Simulate webhook_secret verification passing for "attacker/repo" org/global secret
  Shipit::Command.expects(:start).never
  ContinuousDeliveryJob.expects(:perform_later).with(victim_stack).never

  Shipit::Webhooks::Handlers::StatusHandler.new.process # invoked with attacker_payload

  refute victim_commit.reload.deployable?
end
```
The proof asserts that `Command#start`/`ContinuousDeliveryJob.perform_later` are never invoked for `victim_stack` after only an unrelated repository's webhook signature was verified, demonstrating that `StatusHandler#process` currently has no such guard (the assertion would fail against current code because the lookup is SHA-only and unscoped).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
