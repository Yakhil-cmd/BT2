### Title
Webhook signature verification keys on `repository.owner.login` while every handler resolves the target using `repository.full_name`, allowing a valid multi-tenant App owner to sync another organization's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to validate a payload against using `repository.owner.login` (or `organization.login`), while `Shipit::Webhooks::Handlers::Handler#repository_name` and every concrete handler (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using the independent `repository.full_name` field of the same, attacker-authored JSON body. In a multi-organization Shipit deployment (documented in `docs/setup.md` "Using Multiple Github Applications"), an operator of one onboarded org can self-sign an arbitrary payload with their own known `webhook_secret` and set `full_name` to a different org's repo, causing `PushHandler#process` to call `stack.sync_github(expected_head_sha:)` on a stack it never authenticated for.

### Finding Description
The broken binding is: **organization owning the verified `webhook_secret` (derived from `params.dig('repository','owner','login')`)** should equal **organization owning `repository.full_name`** (derived from `payload.dig('repository','full_name')`), used by `Handler#stacks`/`#repository_name` and consumed unchanged by `PushHandler#process`.

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `github_app = Shipit.github(organization: repository_owner)` and `repository_owner` reads only `repository.owner.login`/`organization.login` (lines 59-62).
- `Shipit.github(organization:)` (lib/shipit.rb:170-181) looks up a per-organization config (`github_app_config`) and instantiates a `GitHubApp`; each configured org has its own independent `webhook_secret` (`lib/shipit/github_app.rb:50,76-83`), verified with `SecureCompare.secure_compare` over the raw body.
- `WebhooksController#create` then dispatches the entire raw JSON body to `Shipit::Webhooks.for_event(event)` handlers (line 12), unrelated to which org's secret matched.
- `Shipit::Webhooks::Handlers::Handler#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:36-38) reads `payload.dig('repository', 'full_name')`, an entirely separate JSON field from `repository.owner.login`.
- `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) uses `stacks` (built from `Repository.from_github_repo_name(repository_name)`) and calls `stack.sync_github(expected_head_sha: params.after)`, where `params.after` is only schema-validated as present (`requires :after`), not tied to any org.
- `Stack#sync_github` (app/models/shipit/stack.rb:612-614) enqueues `GithubSyncJob` for that stack; `GithubSyncJob#perform` (app/jobs/shipit/github_sync_job.rb:18-49) fetches real commits via the *victim's own* `stack.github_api` and, on success, calls `append_commit` → `stack.commits.create_from_github!(gh_commit)`, writing `Commit` rows for the victim stack, and can also enqueue `CacheDeploySpecJob` — records written for a repository whose organization never authenticated the triggering request.

Because the raw POST body is entirely attacker-authored (not GitHub-forwarded), the attacker can make `repository.owner.login = "attacker-org"` (which their own valid `webhook_secret` will verify) while `repository.full_name = "victim-org/victim-repo"` (which every handler actually acts on). No code anywhere cross-checks that these two fields refer to the same organization. `drop_unhandled_event`, the `ExplicitParameters` schema for `push` (only `ref`/`after` required), and `verify_signature`'s `rescue Shipit::GithubOrganizationUnknown` do not address this divergence — they only gate on event type and on whether `attacker-org` exists as a configured org, which it does.

### Impact Explanation
An attacker who legitimately operates one org onboarded to a shared, multi-tenant Shipit instance (with their own valid `webhook_secret`) can force `GithubSyncJob` to run against any other onboarded org's `Stack`/`Repository` records by simply naming that repo's `full_name` in a self-signed payload, at a time and with a chosen `expected_head_sha` of their choosing. This results in `Commit` rows being created and deploy-spec caches being refreshed for a repository/stack that never authenticated the triggering request — matching "a record written for a repository that did not authenticate it." The fetched commit content itself still comes from the victim's real GitHub API (via the victim's own `github_api`), so no forged commit content is injected, but the trigger, timing, and repeated resync are entirely attacker-controlled and repeatable against any/all other tenant stacks known to the attacker. Blast radius is bounded to Shipit deployments configured with multiple GitHub organizations sharing one Shipit instance.

### Likelihood Explanation
Requires the specific, documented multi-tenant configuration (`github:` keyed by multiple organization names in `config/secrets.yml`), and requires the attacker to legitimately control one such tenant org (with knowledge of their own `webhook_secret`, which any App admin of that org has). Given that precondition, the attack is cheap: a single crafted HTTP POST with a valid HMAC computed by the attacker over their own chosen bytes, no live GitHub interaction, no privileged Shipit role, and it is fully repeatable against every repository/stack name the attacker can enumerate or guess (`repository_name`/`full_name` values are visible in Shipit's own UI/URLs).

### Recommendation
Cross-validate that the organization used to select/verify the `webhook_secret` matches the organization embedded in `repository.full_name` (and `organization.login` for org-level events) before dispatching to handlers — e.g., derive `repository_owner` from the same field handlers use, or explicitly compare `repository.owner.login`/`organization.login` against the owner segment of `repository.full_name` and reject (422) on mismatch in `WebhooksController#verify_signature`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "attacker owning attacker-org can sync victim-org's stack by diverging owner.login from full_name" do
  victim_stack = shipit_stacks(:shipit) # repository full_name e.g. "shopify/shipit-engine"
  attacker_org = 'attacker-org'

  payload = {
    'ref' => "refs/heads/#{victim_stack.branch}",
    'after' => 'deadbeefattackerchosen',
    'repository' => {
      'owner' => { 'login' => attacker_org },       # controls which webhook_secret is checked
      'full_name' => victim_stack.repository.full_name # controls which Stack is acted on
    }
  }.to_json

  Shipit.stubs(:github).with(organization: attacker_org).returns(
    stub(verify_webhook_signature: true)
  )

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = 'sha1=attacker-computed-over-own-secret'

  assert_enqueued_with(
    job: GithubSyncJob,
    args: [{ stack_id: victim_stack.id, expected_head_sha: 'deadbeefattackerchosen' }]
  ) do
    post :create, body: payload, as: :json
  end
end
```
This demonstrates: `repository_owner == 'attacker-org'` (signature side) while the handler's `Repository.from_github_repo_name(payload.dig('repository','full_name'))` resolves to `victim_stack`'s repository — the two sides of the binding diverge, and `GithubSyncJob` is enqueued against the victim's stack from an unauthenticated-for-that-org request. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
