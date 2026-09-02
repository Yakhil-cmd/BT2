### Title
Cross-organization webhook forgery: signature is verified against `repository.owner.login`, but the sync target is resolved from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the HMAC signature against using `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body. Every webhook handler (`PushHandler`, `PullRequest::*Handler`, etc.), however, resolves the actual `Repository`/`Stack` to write to using a different field of that same unverified body: `repository.full_name`. In Shipit's documented multi-organization configuration (`config/secrets.development.shopify.yml`, `TOP_LEVEL_GH_KEYS` handling in `lib/shipit.rb`), each organization has its own `webhook_secret`. A holder of a legitimate webhook secret for organization A can therefore forge a signed payload that authenticates as org A but whose `repository.full_name` points at a stack belonging to a completely different organization B, causing Shipit to sync/deploy against org B's stack.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) [2](#0-1) 

The organization used to select the verifying secret (`Shipit.github(organization: repository_owner)`) comes straight from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')` — both attacker-controlled, unauthenticated fields of the raw JSON body, read *before* any signature check succeeds.

`Shipit.github(organization:)` maps each organization name to its own independently configured secret: [3](#0-2) 

This multi-app/multi-secret layout is an explicitly supported and documented configuration: [4](#0-3) 

Meanwhile, every webhook handler picks the `Repository`/`Stack` that will actually be acted upon using a *different* field, `repository.full_name`, via `Handler#stacks`/`Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) 

`PushHandler` then uses that resolved stack to trigger a GitHub sync/deploy pipeline: [7](#0-6) 

The same `repository.full_name`-driven lookup pattern (independent of the field used for signature verification) recurs across the pull-request handlers: [8](#0-7) 

**The broken binding, stated as an equality that the code fails to enforce:**
`organization authenticated by signature (repository.owner.login / organization.login)` **==** `repository whose stack is written (repository.full_name)`

Before the attacker's request: for any legitimately-delivered webhook, GitHub itself guarantees `repository.owner.login` and `repository.full_name`'s owner segment refer to the same repository, so the equality holds implicitly. After the attacker's forged request: the attacker sets `repository.owner.login` to their own organization (so the signature check, keyed on that field, passes with their own legitimate secret) while setting `repository.full_name` to `"<victim-org>/<victim-repo>"`. The controller only checks that *some* org's secret matches; it never checks that the org whose secret validated the signature is the same org that owns the repository the handler is about to mutate.

### Impact Explanation
Any authenticated GitHub App owner in a multi-org Shipit deployment (i.e., someone who legitimately administers their own org's GitHub App and therefore knows their own org's `webhook_secret` — a credential Shipit's own documentation tells them to generate themselves) can forge `push`, `pull_request`, `status`, or `check_suite` events that resolve to a **different** organization's repository/stack. For `push` events this reaches `Stack#sync_github`, which enqueues `GithubSyncJob` and can drive the deploy pipeline for a repository the attacker does not control, and for `pull_request` events it can archive/unarchive or provision Review Stacks belonging to another org. This is a cross-repository/cross-organization write and can lead to an unauthorized deploy trigger, satisfying the "cross-repository writes" / "unauthorized deploy" criteria.

### Likelihood Explanation
This requires (a) the deployment to use the multi-organization GitHub app configuration schema (explicitly documented and supported), and (b) the attacker to control at least one of the configured organizations' GitHub Apps (i.e., to be a legitimate, but lower-privileged, tenant of the shared Shipit instance). Given that condition, exploitation only requires crafting one HTTP POST with a valid HMAC over an attacker-chosen JSON body — no other secret, session, or API token is needed. This is a realistic scenario for any shared/multi-tenant Shipit deployment serving several orgs (exactly the use case the multi-org config exists for).

### Recommendation
After verifying the signature with the secret selected by `repository.owner.login`/`organization.login`, `WebhooksController` (or `Handler#stacks`) must also assert that this same organization matches the owner segment of `repository.full_name` (and of any other repository-identifying field used downstream) before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Shipit is configured with the multi-org schema, e.g. orgs `attacker-org` and `victim-org`, each with its own `webhook_secret`, as in `config/secrets.development.shopify.yml`.
2. Attacker legitimately owns/administers the GitHub App for `attacker-org` and thus knows `attacker-org`'s `webhook_secret`.
3. Attacker builds a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verifies successfully against `attacker-org`'s secret.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and, if the branch matches, calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, triggering sync/deploy activity on `victim-org`'s stack — despite the request never being authenticated by `victim-org`'s secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
