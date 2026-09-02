### Title
Cross-organization webhook confusion allows forging commit CI status and triggering unauthorized deploys - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, then only after that check does it hand the *entire* payload to the event handlers. [1](#0-0) [2](#0-1)  The handlers, however, resolve which `Stack`/`Commit` to mutate independently of that organization, using only `repository.full_name` (`Handler#stacks`/`#repository_name`) or, in the case of `StatusHandler`, using no repository scoping at all. [3](#0-2) [4](#0-3) 

### Finding Description
Shipit supports a multi-tenant configuration where each GitHub organization has its own App config, including its own `webhook_secret` (`Shipit.github_app_config`, `TOP_LEVEL_GH_KEYS`). [5](#0-4)  The equality that the system implicitly relies on is: *the organization whose secret validated the HMAC signature* == *the organization that owns the repository/commit actually mutated by the handler*. That binding is never enforced.

`verify_signature` picks the verifying `GitHubApp` via `repository_owner`, which is read straight out of the unauthenticated JSON body (`params.dig('repository','owner','login')`). [1](#0-0)  Once the raw body's HMAC matches *that* organization's `webhook_secret`, the whole body is passed unmodified to the registered handler. [6](#0-5) 

`StatusHandler`, used for the GitHub `status` event, does not scope its work to any repository at all — it looks up `Commit.where(sha: params.sha)` across the entire Shipit instance and creates a status on every matching commit, regardless of which stack/repository/organization owns it. [4](#0-3)  The `params` schema for this handler requires only `sha`, `state`, and optional descriptive fields — it does not require or check `repository` at all. [7](#0-6) 

Consequently, anyone who legitimately possesses the `webhook_secret` for organization A (e.g., a repository/organization admin on GitHub for org A, which is a normal, low-privilege operational credential from Shipit's point of view — Shipit trusts whichever org owner configured the webhook on the GitHub side) can send a `status` event payload whose HMAC is computed with org A's secret, yet whose `sha`/`state` correspond to a commit belonging to an entirely different, unrelated Shipit-tracked stack/organization B. The signature check only proves "this request was signed by someone holding org A's secret" — it proves nothing about which repository's data the payload is allowed to affect, and the handler never re-checks that.

### Impact Explanation
A forged `status` webhook lets an attacker who controls org A's webhook secret create arbitrary CI check statuses (e.g., `state: "success"`) on commits belonging to org B's stacks. [4](#0-3)  Because commit deployability and continuous delivery gating in `Stack`/`Commit` rely on recorded statuses/checks, injecting a fabricated "success" status can make an otherwise-unreviewed or failing commit appear deployable, and if the target stack has continuous deployment enabled, this can cause `trigger_continuous_delivery`/`ContinuousDeliveryJob` to automatically deploy that commit. [8](#0-7)  This is an unauthorized-deploy path reachable purely by crossing an organizational trust boundary that the signature check was supposed to enforce, not by compromising org B's own credentials.

### Likelihood Explanation
Exploitability requires the attacker to hold a valid `webhook_secret` for *some* organization configured in the same Shipit instance — a credential far weaker than a GitHub App private key or an `ApiClient` token, and one that is routinely handed to repository/org administrators for wiring up the GitHub webhook. In any Shipit deployment onboarding more than one GitHub organization (the multi-tenant config path is explicitly supported via `Shipit.github_app_config`), this is a realistic insider/cross-tenant threat: a low-trust org admin escalates into affecting a higher-trust org's deploy pipeline.

### Recommendation
Bind the two checks together: after verifying the signature for organization X, reject the request (or scope every handler's lookups) so that any `repository.full_name`/`owner.login` referenced in the payload, and every `Commit`/`Stack` mutated by the handler, must belong to that same organization X. Concretely, `Handler#stacks`/`#repository_name` and `StatusHandler#process` should filter by the verified organization, and `WebhooksController` should pass the verified organization down to `Webhooks.for_event(event).each { |handler| handler.call(params, organization: repository_owner) }` so handlers can enforce the constraint instead of trusting unauthenticated payload fields for authorization decisions.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `org-a` and `org-b`, each with its own `webhook_secret` (multi-tenant `secrets.github` config, per `Shipit.github_app_config`).
2. Attacker (holding `org-a`'s `webhook_secret`, e.g. as an `org-a` repo admin) computes `sha256=... ` (per `verify_webhook_signature`, actually `sha1=` per current implementation) over a `status` event JSON body: `{"repository": {"owner": {"login": "org-a"}, "full_name": "org-a/whatever"}, "sha": "<commit sha belonging to org-b's tracked stack>", "state": "success", ...}`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` (derived from `repository.owner.login`) and validates the HMAC against `org-a`'s secret — it passes, since the attacker legitimately holds that secret. [1](#0-0) 
4. `StatusHandler.call(params)` runs `Commit.where(sha: params.sha)` and creates a `success` status on the org-b commit, with no check that the commit belongs to `org-a`. [4](#0-3) 
5. If org-b's stack has `continuous_deployment` enabled and this status satisfies its CI requirement, the forged status can trigger an automatic, unauthorized deploy of that commit via `Stack#trigger_continuous_delivery`. [8](#0-7)

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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
