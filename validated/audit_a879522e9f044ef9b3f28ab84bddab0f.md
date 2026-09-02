### Title
Repository-owner used for webhook signature selection is decoupled from repository.full_name used for stack lookup, enabling cross-tenant `ReviewStack` unarchival - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to validate a request against using `repository.owner.login` (or `organization.login`) from the raw JSON body, while `ReopenedHandler` (via `ReviewStackAdapter`, scoped to `repository.review_stacks`) resolves the *target* repository/stack using the independent `repository.full_name` field from the same body. Because nothing enforces that these two attacker-controlled fields refer to the same repository, in a multi-organization Shipit deployment an entity that legitimately knows one tenant's (`attacker-org`) `webhook_secret` can sign a payload whose `repository.full_name` names a different tenant's (`victim-org`) repository, and have `stack.unarchive!` executed against `victim-org`'s `ReviewStack`.

### Finding Description
The binding that should hold is: `org used to select/verify webhook_secret (repository_owner) == org owning the Repository whose review_stacks are mutated (repository.full_name.split('/').first)`.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-49` computes `repository_owner` from `params.dig('repository','owner','login')` (fallback `organization.login`), and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `lib/shipit.rb#github` resolves per-organization config via `github_app_config(organization)` only when `github_default_organization` is non-nil, i.e. only in the documented **multi-org** configuration (`docs/setup.md`, "Using Multiple Github Applications"). Each org key maps to its own `webhook_secret`. [3](#0-2) 
- Separately, `create` re-parses the same raw body and dispatches it unchanged to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
- `Handler#initialize` parses that same body through the `ExplicitParameters` schema, which for `ReopenedHandler` only requires `repository.full_name` — it does not require or cross-check `repository.owner.login`. [5](#0-4) 
- `ReopenedHandler#repository` resolves the target `Repository` purely from `params.repository.full_name`, independent of whatever org was used to verify the signature. [6](#0-5) 
- `ReopenedHandler#process` then calls `stack.unarchive!` where `stack` is a `ReviewStackAdapter` scoped to `repository.review_stacks` (i.e., `victim-org`'s repository), if `unarchive?` (driven by `repository.review_stacks_enabled` and `provisioning_behavior_*`) is true. [7](#0-6) [8](#0-7) [9](#0-8) 

Exploit request: a tenant/party that legitimately controls `attacker-org`'s configured GitHub App (and therefore knows `attacker-org`'s `webhook_secret` in a multi-org Shipit deployment) sends `POST /webhooks` with `X-Github-Event: pull_request`, a valid `X-Hub-Signature` computed with `attacker-org`'s secret, and a body:
```json
{
  "action": "reopened",
  "number": 1,
  "pull_request": { ... valid schema fields ... },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
`verify_signature` selects and validates against `attacker-org`'s secret (which the attacker legitimately possesses) and passes. The handler then acts on `victim-org/victim-repo` because it reads `repository.full_name` independently, calling `stack.unarchive!` on `victim-org`'s `ReviewStack` if that repository has `review_stacks_enabled` and a matching `provisioning_behavior`.

Why existing guards fail: `verify_signature` only proves "this request was signed by *some* org's key," not "the signing org owns the repository named in the payload." `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/shape of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name`. `Repository.from_github_repo_name` performs no ownership check against the verifying org.

Note: this path is only reachable in the **multi-organization** GitHub App configuration (`secrets.github` keyed by org name). In the default single-org configuration, `Shipit.github` ignores the `organization:` argument and always uses the single global `webhook_secret`, so the org-name field in the payload has no effect on which secret is checked, and this specific confusion does not apply there — an attacker without that single secret still cannot forge any signature.

### Impact Explanation
In a multi-tenant Shipit instance, a party in control of one tenant's (`attacker-org`) webhook secret can trigger `stack.unarchive!` (and the identical class of bug applies to `LabeledHandler`/`UnlabeledHandler` archive/unarchive) against another tenant's (`victim-org`) `ReviewStack`, without any authenticated relationship to `victim-org`. This is a cross-tenant stack-state mutation triggered by a payload naming another repository — matching the Critical category "a payload for one repository mutating another's stack." Repeatable per request; blast radius covers every `ReviewStack`-enabled repository across every configured org in a multi-org deployment.

### Likelihood Explanation
Requires: (1) Shipit configured with multiple GitHub organizations (`docs/setup.md` "Using Multiple Github Applications"), (2) the attacking party controls a legitimately configured tenant's webhook secret (not a Shipit secret leak, just their own org's GitHub App secret, which such a party would routinely possess as the admin of their own integrated org), and (3) `victim-org`'s target repository has `review_stacks_enabled` with a `provisioning_behavior` satisfied by attacker-supplied labels/state. Given these preconditions are specific to multi-org deployments, likelihood is moderate — it does not apply to the more common single-org setup.

### Recommendation
In `WebhooksController`/`Handler`, after signature verification, assert that the org used to verify the signature (`repository_owner`) matches the owner segment of `repository.full_name` used by the handler (i.e., reject or drop events where `params.dig('repository','owner','login')&.downcase != full_name.split('/').first`). Alternatively, have handlers resolve the `Repository` only within the same org that authenticated the request, rather than trusting `repository.full_name` in isolation.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, multi-org config):
1. Stub `Shipit.secrets.github` with two orgs: `attacker-org` (secret `S_A`) and `victim-org` (secret `S_V`).
2. Create `victim-org/repo` with `review_stacks_enabled: true`, `provisioning_behavior: allow_all`, and an archived `ReviewStack` (`environment: "pr1"`).
3. Build a `pull_request` "reopened" JSON body with `repository: {owner: {login: "attacker-org"}, full_name: "victim-org/repo"}`.
4. Compute `X-Hub-Signature` using `S_A` (attacker-org's secret, known to the attacker).
5. `post :create, body: payload, as: :json` with that signature header.
6. Assert response is `:ok` (signature accepted for `attacker-org`).
7. Assert `victim_stack.reload.archived?` is `false` (transitioned from archived to active), proving `victim-org`'s stack was unarchived despite the request being verified against `attacker-org`'s secret — i.e. `verifying_org ("attacker-org") != owning_org ("victim-org")` yet the mutation still occurred.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L55-59)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
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
