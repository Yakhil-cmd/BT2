### Title
Cross-organization webhook forgery via mismatched signature-verification vs. repository-resolution fields in multi-tenant GitHub App config - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization deployments (documented and tested via `test/dummy/config/secrets_double_github_app.yml`), Shipit allows configuring one GitHub App/webhook secret per GitHub organization [1](#0-0) . The controller picks *which* organization's secret to verify the inbound webhook signature against using `repository.owner.login` (falling back to `organization.login`), but the actual handlers that mutate application state resolve the target repository/stack from an entirely different, unauthenticated-relative field: `repository.full_name` [2](#0-1) . These two JSON fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) to validate the payload against using: [3](#0-2) [4](#0-3) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')`. `Shipit.github(organization: repository_owner)` looks up the per-organization config and its `webhook_secret` [1](#0-0) .

Once the signature check passes, `create` dispatches the *entire raw payload* to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

Handlers such as `PushHandler` and `CheckSuiteHandler` do not use `repository.owner.login` at all — they resolve the target `Repository`/`Stack` from `repository.full_name` via `Handler#repository_name`/`#stacks`: [2](#0-1) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` performs a global lookup by `owner/name` with no scoping to which GitHub App/organization authenticated the request: [8](#0-7) 

Because HMAC-SHA1 signs the *entire* raw body, an attacker cannot forge a signature for a secret they don't know. However, in the documented multi-org setup, each org's webhook secret is legitimately known to that org's own GitHub App owner/administrator (they configured it). Nothing in Shipit's model prevents Org A's administrator/webhook secret holder from crafting and sending a payload where `repository.owner.login` (and/or `organization.login`) is set to `"OrgA"` (so `verify_signature` picks OrgA's `webhook_secret` and passes) while `repository.full_name` is set to `"OrgB/some-repo"` (a repository actually belonging to a different tenant/org configured on the same Shipit instance). The signature check validates only that OrgA's secret was used — it never confirms that `repository.full_name`'s owner matches the organization whose secret validated the signature.

This breaks the binding: **organization that authenticated (via webhook_secret lookup on `repository.owner.login`) == repository that is written (resolved via `repository.full_name`)**. These are two independent fields inside one signed JSON body, and the code equates "signature is valid for the org derived from field A" with "it's safe to act on the repository named in field B," which is not the same guarantee.

### Impact Explanation
An operator/administrator of one tenant organization's GitHub App (who legitimately possesses that org's `webhook_secret`, an unprivileged actor with respect to any *other* tenant configured on the same Shipit instance) can forge webhook events that are processed as if they originated from another organization's repository. Concretely:
- `PushHandler` triggers `GithubSyncJob`/`stack.sync_github` for stacks belonging to a repository the attacker does not control.
- `StatusHandler` calls `commit.create_status_from_github!`, which can flip a commit's computed `deployable?` state and fire `schedule_merges`/continuous-deployment logic for a foreign org's stack [9](#0-8) , potentially causing an **unauthorized deploy** on a stack the attacker has no legitimate access to — this crosses the "unauthorized deploy" / "cross-repository writes" impact bucket.
- `CheckSuiteHandler` similarly triggers `schedule_refresh_check_runs!` on a foreign stack's commits.

This is only exploitable in the documented multi-organization configuration (`Using Multiple Github Applications` in `docs/setup.md`) where distinct, mutually-untrusting organizations share a single Shipit instance and each brings its own webhook secret — a supported, in-scope tenancy model, not a misconfiguration outside the documented deployment.

### Likelihood Explanation
Requires: (1) the target Shipit instance to be configured with multiple GitHub organizations (a documented, tested configuration — `test/dummy/config/secrets_double_github_app.yml`, `test/unit/shipit_test.rb`), and (2) the attacker to be the legitimate holder of one configured org's `webhook_secret` (e.g., an admin of that org's GitHub App) while being unprivileged with respect to the other org(s)/repos hosted on the same instance. This is a realistic tenancy-isolation failure for any shared/multi-tenant Shipit deployment, though it does not apply to the common single-organization deployment.

### Recommendation
After signature verification selects an organization, re-derive and enforce that the organization embedded in the payload's `repository.full_name` (or `repository.owner.login`) matches the organization whose secret validated the signature, rejecting (422) any mismatch before dispatching to handlers. Alternatively, scope `Repository.from_github_repo_name` lookups (and thus all webhook handler side effects) to only repositories belonging to the verified organization.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-app schema), and a Repository `OrgB/target-repo` with an active stack.
2. As the holder of `OrgA`'s webhook secret, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
signed with `OrgA`'s `webhook_secret` via `X-Hub-Signature`.
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully (using `OrgA`'s secret, which the attacker legitimately knows) [10](#0-9) .
4. `PushHandler#process` resolves stacks via `repository.full_name` = `"OrgB/target-repo"` [2](#0-1)  and enqueues `GithubSyncJob`/triggers sync for `OrgB`'s stack, despite the attacker having no relationship to `OrgB`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
