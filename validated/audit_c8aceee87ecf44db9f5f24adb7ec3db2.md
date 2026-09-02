### Title
Missing per-repository authorization in `StatusHandler#process` allows cross-repository/cross-stack Status writes - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Api::BaseController` scopes every mutation to `current_api_client.stack_id` via `stacks`/`require_permission!`, but the webhook ingestion path has no equivalent per-repository check for the `status` event. `StatusHandler#process` looks up commits globally by `sha` with no repository/stack scoping, unlike `PushHandler`, which explicitly scopes to `stacks` derived from the payload's `repository.full_name`.

### Finding Description
The claimed binding — "authorization enforced on the webhook ingestion path for repository-scoped mutations == authorization enforced on the equivalent API path" — does not hold.

On the API side, `Shipit::Api::BaseController#stacks` restricts all queries to `current_api_client.stack_id` when the token is stack-scoped [1](#0-0) , and controllers like `StacksController`/`DeploysController` layer `require_permission!` on top of that [2](#0-1) .

On the webhook side, `WebhooksController#verify_signature` only validates that the payload's HMAC matches the `webhook_secret` configured for the organization named in `params.dig('repository','owner','login')` (falling back to `organization.login`) [3](#0-2) . This is an organization-level signature check, not a repository- or stack-scoped authorization check. `Shipit.github(organization:)` raises `GithubOrganizationUnknown` (→422) only if the organization isn't configured at all [4](#0-3) ; it performs no check that the specific `repository.full_name` in the payload is the one entitled to mutate the target commit's stack.

The base `Handler` class provides exactly the scoping primitive needed: `stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks` [5](#0-4) . `PushHandler#process` correctly uses it: `stacks.not_archived.where(branch:).find_each { ... }` [6](#0-5) .

`StatusHandler#process`, however, never calls `stacks` at all — it does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [7](#0-6) . This query is global across the entire `commits` table, with no filter tying the matched commit's `stack`/`repository` back to `payload.dig('repository','full_name')`. Given the sha-collision precondition already established elsewhere in this audit, a status payload whose signature is valid for organization X can write a `Status` onto any `Commit` row anywhere in the database that happens to share that sha — including commits belonging to stacks under a completely different repository/organization, since nothing in `verify_signature` or `StatusHandler#process` re-validates that the reporting repository owns the matched commit's stack.

None of the listed guards close this gap: `verify_signature` authenticates the org, not the repository-to-stack relationship; `ExplicitParameters` (`requires :sha, String`) only validates types, not ownership; `drop_unhandled_event` only filters unknown event types; and no `Repository`/`Stack` model validation is invoked in this path at all.

### Impact Explanation
A successfully signature-verified `status` webhook from one organization/repository can cause a `Status` record to be written onto a `Commit` belonging to a stack under an unrelated repository, because `StatusHandler#process` has no analogue of `Api::BaseController#stacks`/`require_permission!`. This is a missing-authorization defect on a repository-scoped mutation path, matching the "payload for one repository mutating another's...commit" Critical category, contingent on the previously-established sha-collision precondition being satisfiable. Repeatable for every sha collision the attacker can produce, against any stack whose commit shares that sha.

### Likelihood Explanation
The attacker still needs (a) a webhook whose signature passes `verify_webhook_signature` for some organization already configured in Shipit's `secrets.github`, and (b) a colliding `sha` with a commit belonging to a stack outside that organization/repository (the stated precondition). Given those, no additional Shipit secret, session, or `ApiClient` permission is required — `StatusHandler` performs zero repository/stack authorization, so the org-level signature check is the only gate and it structurally cannot enforce repository-to-stack ownership.

### Recommendation
Add repository/stack scoping to `StatusHandler#process` mirroring `Handler#stacks`/`PushHandler`: restrict the `Commit` lookup to `stacks` (i.e., `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or equivalent), so a status payload can only mutate commits belonging to stacks under the repository named in that payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "StatusHandler does not create a status for a commit belonging to a different repository's stack" do
  other_stack   = shipit_stacks(:cyclimse) # belongs to a different repository than :shipit
  other_commit  = other_stack.commits.create!(sha: 'deadbeef' * 5, author: shipit_users(:cyclimse), authored_at: Time.now, committer: shipit_users(:cyclimse), committed_at: Time.now)

  payload = {
    'sha' => other_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'shopify/not-that-repo', 'owner' => { 'login' => 'shopify' } }
  }

  assert_no_difference -> { other_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end

# contrast: test/controllers/api/stacks_controller_test.rb-style
test "Api request scoped to a different stack is rejected" do
  authenticate!(stack: shipit_stacks(:shipit)) # ApiClient scoped to :shipit only
  post :create, params: { repo_owner: 'cyclimse', repo_name: 'other-repo', environment: 'production', branch: 'main' }
  assert_response :forbidden # or 401/404 depending on scope enforcement
end
```
Both sides of the equality diverge: the API path rejects the cross-stack mutation via `stacks`/`require_permission!`, while the webhook path (`StatusHandler#process`) performs the cross-stack mutation successfully because it has no equivalent scoping check.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L5-6)
```ruby
    class DeploysController < BaseController
      require_permission :deploy, :stack
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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
