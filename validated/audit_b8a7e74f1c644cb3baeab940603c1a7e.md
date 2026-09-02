Confirmed root-cause chain. This is a genuine vulnerability.

### Title
Webhook signature verification authenticates the payload's `repository.owner.login` organization but every event handler acts on the independently-attacker-controlled `repository.full_name` field, allowing cross-organization webhook forgery — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), a value taken from the very same untrusted JSON body being verified. Once the HMAC check passes with *that* organization's `webhook_secret`, the entire raw body is treated as trusted and dispatched to handlers. But every handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, and duplicated logic in the pull-request handlers and `ReviewStackAdapter`) determines which `Repository`/`Stack` to mutate using a *different* field from the same payload: `repository.full_name`. In a multi-organization Shipit deployment (the engine explicitly supports this, see `config/secrets.development.shopify.yml` and `Shipit.github_app_config`), an attacker who legitimately controls a GitHub App installation for Organization A (and therefore knows Organization A's `webhook_secret`) can sign a payload with `repository.owner.login = "OrgA"` while setting `repository.full_name = "OrgB/target-repo"`. Signature verification succeeds using OrgA's secret, yet the handler dispatches actions against OrgB's stacks — an organization that authenticated versus the repository that is written.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` picks the `github_app` via `Shipit.github(organization: repository_owner)`, where `repository_owner` reads `params.dig('repository', 'owner', 'login')` (fallback `organization.login`). [1](#0-0) [2](#0-1) 
- `Shipit.github(organization:)` looks up per-organization config (secret, private key) via `github_app_config`, supporting the documented multi-org secrets layout. [3](#0-2) 
- Once `verify_webhook_signature` succeeds (HMAC over the full raw body using the resolved organization's `webhook_secret`), `WebhooksController#create` parses the same JSON and dispatches it to all registered handlers. [4](#0-3) 
- Handlers resolve the target repository/stack from an entirely separate field, `repository.full_name`, not `repository.owner.login`. [5](#0-4) 
- The same pattern repeats in pull-request handlers (`ClosedHandler`, `OpenedHandler`, `ReopenedHandler`, `LabelCapturingHandler`) and `ReviewStackAdapter`, all keying repository resolution off `params.repository.full_name` rather than the owner used for signature selection. [6](#0-5) [7](#0-6) 

There is nothing in the code that requires `full_name`'s owner segment to match `repository_owner`/`organization.login`. Because HMAC verification only proves "this byte stream was signed by *some* organization's configured secret," not "this byte stream's `repository.full_name` belongs to that organization," the trust binding `authenticated_org == written_repository_owner` is never enforced.

### Impact Explanation
An attacker who is a legitimate customer/administrator of one GitHub organization configured in a shared multi-org Shipit instance can forge webhook events targeting any other organization's stacks tracked by that same instance:
- `push` events (`PushHandler`) trigger `stack.sync_github(expected_head_sha:)` on arbitrary stacks in a foreign org, forcing GitHub sync with an attacker-chosen `after` SHA. [8](#0-7) 
- `status` events (`StatusHandler`) let the attacker inject a forged `success`/`failure` `Status` for any commit sha, which feeds directly into deploy-readiness/CI-gating (`enable_ci_on_stack`, `schedule_continuous_delivery`), potentially enabling continuous-deployment to fire on a commit that never actually passed CI in the victim org. [9](#0-8) [10](#0-9) 
- `pull_request` events can archive/unarchive/provision review stacks belonging to a foreign org's repository. [11](#0-10) 

This crosses a repository/organization trust boundary and can lead to an unauthorized deploy on a stack the attacker does not control, satisfying the Critical "unauthorized deploy" impact bar, contingent on the deployment actually running multi-organization Shipit with distinct `webhook_secret`s per org as documented.

### Likelihood Explanation
Requires: (1) the Shipit instance configured for multiple GitHub organizations (an explicitly documented and supported configuration), and (2) the attacker controls (or compromises) a legitimate GitHub App installation/webhook secret for at least one of those organizations — which is a normal, low-privilege position for a customer/org-admin, not a Shipit account or `ApiClient` token. Given that, forging the payload is trivial (just crafting JSON and computing HMAC with the known secret).

### Recommendation
After signature verification succeeds, re-derive the organization/owner strictly from the same `repository_owner` value used to select the secret, and reject (or ignore) any event where `repository.full_name`'s owner segment (or `organization.login`) does not match `repository_owner`. Alternatively, pass the already-authenticated `repository_owner` into the handler pipeline and have `Handler#repository_name`/`ReviewStackAdapter`/pull-request handlers scope `Repository.from_github_repo_name` lookups to that verified owner instead of trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. As an attacker who is the GitHub App owner for `OrgA` (knows `OrgA`'s `webhook_secret`), craft a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and set `X-Github-Event: push`.
4. POST to `/webhooks`. `verify_signature` resolves `repository_owner` → `"OrgA"`, uses `OrgA`'s secret, and the signature validates.
5. `PushHandler#process` (via `Handler#repository_name` → `payload.dig('repository','full_name')`) looks up `OrgB/victim-repo` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack the attacker has no authorization over.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
