I found the binding break in `WebhooksController`: the organization used to select the GitHub App for signature verification is derived from the same untrusted request payload that the event handlers subsequently trust to determine which `Repository`/`Stack` to mutate, and these two payload fields are never cross-checked against each other.

### Title
Webhook signature verified against `repository.owner.login`, but processing acts on unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret`) used to validate the HMAC purely from `repository.owner.login` / `organization.login` in the untrusted JSON body [1](#0-0) . Once the signature check passes, `create` re-parses the same raw body and dispatches it to handlers such as `PushHandler` and `Handler#repository_name`, which independently resolve the target `Repository`/`Stack` from `repository.full_name`, a completely different JSON field that is not covered by the organization lookup used for verification [2](#0-1) [3](#0-2) .

### Finding Description
`repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) . This value selects which multi-tenant `GitHubApp` config (and its `webhook_secret`) is used to verify `X-Hub-Signature` against `request.raw_post` [5](#0-4) . However, the actual repository/stack that gets mutated by downstream handlers is resolved from `repository.full_name`, e.g. `Handler#repository_name` / `Repository.from_github_repo_name` [6](#0-5) , and `PushHandler#process` triggers `stack.sync_github` for any stack matching the branch under that repository [3](#0-2) . The binding that should hold is: `organization used to verify signature == organization owning the repository/stack actually mutated`. Since `repository.owner.login` and `repository.full_name`'s owner segment are never cross-validated for equality, an operator with legitimate write access to one organization's webhook secret (i.e., a customer who owns a configured GitHub App under Shipit's multi-org support in `Shipit.github(organization:)` [7](#0-6) ) can craft a payload where `repository.owner.login` names their own org (so the signature check passes with their own secret) while `repository.full_name` names a `Repository`/`Stack` belonging to a different organization/tenant hosted on the same Shipit instance, causing cross-repository sync/state changes to be triggered outside the org whose secret was actually verified.

### Impact Explanation
This crosses the "organization authenticated vs repository written" boundary explicitly called out as in-scope: the signature check authenticates one organization's webhook, but the mutation (`GithubSyncJob`, commit/status ingestion, stack unarchiving, PR/review-stack creation) is applied to a repository under a different, unauthenticated organization. This is a cross-tenant write achieved without possessing the secret of the org actually affected, matching "cross-repository writes" impact criteria.

### Likelihood Explanation
Exploitability depends on Shipit being configured with more than one GitHub App / organization (the multi-org code path in `Shipit.github(organization:)`), which is an explicitly supported and documented configuration (`test/dummy/config/secrets_double_github_app.yml`, `GitHubAppsTestOrgOne`/`OrgTwo` tests) [8](#0-7) . Any actor who can get a webhook signed by their own org's configured secret (e.g., a legitimate customer with their own GitHub App installed on the shared Shipit instance) can pick an arbitrary `repository.full_name` value.

### Recommendation
Validate that the organization derived for signature verification also matches the owner of `repository.full_name` (or `organization.login`) used by the event handlers before dispatching, e.g. reject the webhook if `repository.owner.login` and the parsed owner segment of `repository.full_name` diverge, and thread the verified organization through to `Handler#repository_name` resolution rather than trusting the payload twice independently.

### Proof of Concept
1. Configure Shipit with two GitHub Apps for `org-a` and `org-b` (as supported by `Shipit.github(organization:)`).
2. As an operator who legitimately controls `org-a`'s webhook secret, compute a valid HMAC over a JSON body where `repository.owner.login = "org-a"` (so `verify_signature` succeeds using `org-a`'s `webhook_secret`) but `repository.full_name = "org-b/some-repo"`.
3. POST this payload to `/webhooks` with event `push`.
4. `verify_signature` passes (uses `org-a`'s app/secret). `create` dispatches to `PushHandler`, which resolves the target repository via `repository.full_name` = `org-b/some-repo`, and triggers `GithubSyncJob`/stack updates for a stack that belongs to `org-b`, which the request was never authenticated for.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
    end
```
