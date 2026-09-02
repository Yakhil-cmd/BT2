### Title
Webhook signature verification selects the signing organization by `repository.owner.login`, but handlers dispatch on the unrelated `repository.full_name` field, decoupling "which org's secret authenticated this request" from "which stack gets written to" - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to HMAC-verify the raw webhook body against using `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw payload to handlers such as `PushHandler`, which locate the target `Stack` via `Handler#repository_name`, a *different* JSON field: `payload.dig('repository', 'full_name')` [2](#0-1) , and act on it (`stack.sync_github`) [3](#0-2) .

### Finding Description
Shipit supports multiple GitHub Apps/organizations, each with its own independently configured `webhook_secret` keyed by organization name [4](#0-3) . `GitHubApp#verify_webhook_signature` HMACs the raw body against the secret for whichever organization was selected: `return true unless webhook_secret` — i.e., if that organization has no `webhook_secret` configured, verification unconditionally succeeds regardless of the signature header supplied [5](#0-4) . The test fixtures confirm `webhook_secret` is an accepted, legitimate `nil` configuration for a configured organization [6](#0-5) .

Crucially, the field used to select *which org's secret authenticates the request* (`repository.owner.login`) and the field used to select *which stack the handler actually writes to* (`repository.full_name`) are two independent JSON keys inside the same attacker-controlled body, and the code never checks that they refer to the same organization. So the equality that should hold — `verified_organization == owning_organization(stack_written_to)` — is not enforced anywhere in `WebhooksController` or `Shipit::Webhooks::Handlers::Handler`.

### Impact Explanation
For any organization configured without a `webhook_secret` (a supported, non-default but legitimate state per the config schema), any unauthenticated caller can submit a `push`/`check_suite`/`status` webhook body where `repository.owner.login` is set to that unsecured org (bypassing signature verification entirely) while `repository.full_name` is set to a completely unrelated stack belonging to a different, properly secured organization. `PushHandler#process` will look that repo up via `Repository.from_github_repo_name` and invoke `stack.sync_github(expected_head_sha: ...)`, enqueueing `GithubSyncJob`, which fetches and appends new commits and can feed `ContinuousDeliveryJob`/deploy triggers for a stack the attacker has no legitimate relationship with. This crosses the "unauthorized action on a stack the caller does not control" boundary despite `verify_signature` reporting a successful check.

### Likelihood Explanation
This does not require possession of any `webhook_secret`, `api_clients_secret`, or session/API token — only knowledge that some organization in the deployment's multi-org GitHub App config has left `webhook_secret` unset (a state the schema explicitly allows, as shown in the fixtures) and the target stack's `full_name`. Because `github_organizations`/`github_app_config` are configuration-driven and per-org, this is realistically encountered in any multi-tenant Shipit deployment where at least one onboarded organization has not set a webhook secret.

### Recommendation
Bind signature verification to the field actually used for write-side dispatch: verify against `repository.full_name`'s owning organization (or, better, resolve the target `Stack`/`Repository` first, determine its configured organization, and verify the signature using that organization's secret) rather than trusting a separately-supplied `repository.owner.login`/`organization.login`. Also consider making `webhook_secret` mandatory per configured organization rather than silently permitting unauthenticated bypass when absent.

### Proof of Concept
1. Deploy Shipit with two organizations configured: `OrgA` (no `webhook_secret`) and `OrgB` (has a stack `orgB/secret-repo` with `webhook_secret` set), mirroring `test/dummy/config/secrets_double_github_app.yml` [6](#0-5) .
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "orgB/secret-repo" }
}
```
No `X-Hub-Signature` (or any arbitrary value) is required since `verify_webhook_signature` short-circuits to `true` for `OrgA` [7](#0-6) .
3. `verify_signature` resolves `repository_owner` to `"OrgA"` [1](#0-0)  and passes.
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves the stack via `full_name: "orgB/secret-repo"` [2](#0-1)  and calls `stack.sync_github`, enqueueing `GithubSyncJob` for `OrgB`'s stack [3](#0-2) [8](#0-7) , entirely unauthenticated with respect to `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
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
```
