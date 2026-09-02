### Title
Webhook signature verification binds the trusted GitHub organization to `repository.owner.login`/`organization.login`, but every event handler acts on the unrelated `repository.full_name` field, allowing a trusted org's webhook secret to forge events for any other tracked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App (and thus the `webhook_secret` used to validate the HMAC signature) based on `repository.owner.login` (falling back to `organization.login`), but `Shipit::Webhooks::Handlers::Handler#repository_name`, used by every handler to decide which `Repository`/`Stack` to act on, reads the independent `repository.full_name` field from the same attacker-controlled JSON body. Nothing ties these two fields together, so a party who legitimately controls one configured GitHub organization (and therefore knows its `webhook_secret`) can forge a validly-signed webhook whose `repository.full_name` points at a stack belonging to a completely different, victim organization.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves to a distinct `GitHubApp` instance per organization, each with its own `webhook_secret` in `secrets.github`, which is a first-class supported multi-tenant configuration: [3](#0-2) 

Once the signature check passes for *some* configured organization, the raw payload is dispatched unchanged to all registered handlers: [4](#0-3) 

Every handler determines the repository/stack to operate on from a *different* field of the same payload, `repository.full_name`, with no cross-check against the field used for signature/org selection: [5](#0-4) 

For example, `PushHandler` triggers a GitHub sync for any stack matching that repository/branch, and `StatusHandler` creates a commit status record for any commit matching that sha, purely based on `repository_name`/`sha` looked up globally: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` performs a global, unscoped lookup by owner/name parsed out of `full_name`: [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization used to select/verify the webhook_secret (repository.owner.login / organization.login)` == `repository whose Stack/Commit records the dispatched handler mutates (repository.full_name)`

Before the attack: signature verification is intended to guarantee that only the legitimate owner of a tracked repository/org can inject events for that repository.
After the attack: an entity that only owns/controls org A (with its own valid `webhook_secret`) can compute a valid signature for a payload whose `repository.full_name` names org B's repository, and every handler will act on org B's data as if GitHub itself sent the event for org B.

### Impact Explanation
This breaks the trust boundary between GitHub organizations tracked by a single Shipit instance (a documented, supported deployment topology — "Using Multiple Github Applications"). An attacker who legitimately controls any one configured organization can:
- Inject forged `status` events (`StatusHandler`) that create arbitrary CI/status records against a victim repository's commits, which feed directly into `deployable?`/CI-gating checks used to decide whether a commit can be deployed.
- Force `sync_github`/`check_suite` refreshes and other repository-state mutations for a repository they do not own.

Because commit `Status` records influence deploy gating, this can be used to spoof a passing CI state and enable an otherwise-blocked, unauthorized deploy of a victim stack — this maps to the Critical-tier impact "an unauthorized deploy" defined in scope. At minimum it is unauthenticated cross-organization state injection into repository/commit records that the attacker does not own, which the webhook signature scheme is specifically designed to prevent.

### Likelihood Explanation
Requires only that the Shipit instance is configured with more than one GitHub organization/app (a documented supported configuration) and that the attacker legitimately controls (or has been granted) one of those lower-trust organizations. No `ApiClient` token, `GITHUB_TOKEN`, private key, or session is needed — only the ability to POST directly to the public `/webhooks` endpoint with a payload signed using the attacker's own organization's `webhook_secret`. This is a straightforward, reliably-reproducible attack rather than a probabilistic/timing-dependent one.

### Recommendation
Require that the field used to select/verify the webhook secret and the field used to resolve the acted-upon repository come from the same, cross-validated source. Concretely, in `WebhooksController#verify_signature` and/or `Handlers::Handler#repository_name`, ensure `repository.full_name`'s owner segment matches the organization that was used to validate the signature (`repository_owner`/`organization.login`), and reject the webhook (422) if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `org-attacker` and `org-victim`, each with its own `webhook_secret` (per the documented multi-org `secrets.yml` format).
2. As the operator of `org-attacker` (who legitimately knows `org-attacker`'s `webhook_secret`), craft a `push` (or `status`) webhook JSON body where:
   - `repository.owner.login` = `"org-attacker"` (or `organization.login` = `"org-attacker"`)
   - `repository.full_name` = `"org-victim/target-repo"`
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-attacker's webhook_secret, raw_body)>`.
4. POST this payload to `/webhooks` with header `X-Github-Event: push` (or `status`).
5. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` and the signature validates successfully.
6. `PushHandler`/`StatusHandler` resolve the target repository via `payload.dig('repository', 'full_name')` = `"org-victim/target-repo"`, and mutate `org-victim`'s stacks/commits (e.g., create a forged "success" status on a victim commit) even though the attacker has no relationship to `org-victim`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-26)
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
    end
  end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
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
