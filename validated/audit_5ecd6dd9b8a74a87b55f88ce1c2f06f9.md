### Title
Webhook signature verification authenticates a payload's `repository.owner.login` while all business logic acts on the unverified `repository.full_name` field, allowing cross-organization event forgery when any configured GitHub App has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which HMAC secret) to validate a webhook against based on `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. [1](#0-0) [2](#0-1)  Every downstream handler, however, resolves the repository/stack to act on using the separate `repository.full_name` field from the same payload, never re-checking that it corresponds to the organization whose secret validated the request. [3](#0-2) 

### Finding Description
Shipit supports multiple GitHub App configurations keyed by organization name, each with its own independent `webhook_secret` [4](#0-3) . `GitHubApp#verify_webhook_signature` explicitly short-circuits to `true` when no secret is configured for that organization: `return true unless webhook_secret`. [5](#0-4) 

The controller uses `repository_owner` (from `repository.owner.login`, falling back to `organization.login`) purely to pick *which* app/secret to validate against; the HMAC check is only meaningful for the org selected by that field. [1](#0-0)  But the actual repository being written to is resolved independently by every handler via `payload.dig('repository', 'full_name')` and `Repository.from_github_repo_name(...)`, e.g. in the base `Handler` class and in `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `ReviewStackAdapter`. [3](#0-2) [6](#0-5) [7](#0-6) 

Nothing enforces that `repository.owner.login` (verified organization) equals the organization prefix inside `repository.full_name` (organization actually written to). Because `repository_owner` and `repository.full_name` are independent JSON fields under attacker control in an unsigned request, an attacker who knows one organization in the multi-org `Shipit.github` configuration has no `webhook_secret` set (a supported configuration, as shown in the shipped example config with `webhook_secret: nil`) can craft a payload where:
- `repository.owner.login` / `organization.login` = the org with **no** secret (selects the app whose `verify_webhook_signature` always returns `true`)
- `repository.full_name` = `"other-org/other-repo"`, an arbitrary stack tracked under a **different**, properly-secured organization

The request sails through `verify_signature` unauthenticated, and `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [8](#0-7)  then dispatches to handlers that act on `other-org/other-repo` based purely on `repository.full_name`.

This breaks the equality the engine implicitly relies on: `organization authenticated (repository_owner) == repository written (repository.full_name)`. Before the attack these are always consistent for genuine GitHub-originated webhooks; after a forged request they diverge, letting an attacker impersonate GitHub for any tracked repository as long as one org in the fleet lacks a secret.

### Impact Explanation
Concretely reachable, unauthenticated writes include:
- `PushHandler#process` calling `stack.sync_github(expected_head_sha: params.after)` on stacks matched by the forged `repository.full_name`/`branch`, forcing a sync against an attacker-chosen SHA. [9](#0-8) 
- Forged `pull_request` "opened"/"closed"/"reopened" events causing `ReviewStackAdapter` to create, archive, or unarchive review stacks (which triggers `stack.deprovision` / provisioning queue changes) for a repository the attacker does not control and never signed for. [10](#0-9) 

This matches the in-scope "Critical: cross-repository writes / unauthorized deploy or rollback" impact class, since the write target (`repository.full_name`) is never bound to the organization that was cryptographically verified.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one configured GitHub App organization with a blank/unset `webhook_secret` while other organizations are tracked with real secrets — a configuration the shipped example secrets file explicitly demonstrates as valid (`webhook_secret: # nil`). [11](#0-10)  In any multi-organization Shipit deployment where even one org's secret is left unset (e.g., during onboarding, a demo/staging org, or an org intentionally left open), the entire cross-organization forgery becomes trivially exploitable by an anonymous, unauthenticated attacker who only needs to know that org's login name.

### Recommendation
- Require and enforce a non-blank `webhook_secret` for every configured GitHub App organization; never allow `verify_webhook_signature` to trivially return `true`.
- After signature verification succeeds, assert that the organization used to select the verifying secret (`repository_owner`) matches the organization prefix of `repository.full_name` (and `organization.login` when present) before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with a multi-org GitHub config where `orgA` has `webhook_secret: nil` and `orgB` (tracking a real stack `orgB/repo`) has a secret set.
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "orgB/repo", "owner": { "login": "orgA" } }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `verify_webhook_signature` returns `true` unconditionally since `orgA` has no secret. [5](#0-4) 
4. `PushHandler` resolves stacks via `repository.full_name` = `"orgB/repo"` and forces `sync_github` on the real `orgB/repo` stack — without ever presenting a valid signature for `orgB`. [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
