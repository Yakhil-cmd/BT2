### Title
Webhook signature verification is keyed to `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing an attacker holding one organization's webhook secret to write into another organization's repositories/stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, the `WebhooksController` selects which `GithubApp`/webhook secret to verify a payload's signature against using only `repository.owner.login` (or `organization.login`) from the untrusted JSON body, while every event `Handler` resolves the repository/stack to act on using the sibling `repository.full_name` field from that same body. These two fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret purely from a field inside the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization config/secret in `Rails.application.credentials.github` and instantiates/reuses a `GitHubApp` keyed by that organization string: [3](#0-2) 

The HMAC verification itself (`GithubApp#verify_webhook_signature`) is generic and secret-agnostic — it just compares the HMAC of the raw body against the signature header using whichever `webhook_secret` was resolved for `repository_owner`: [4](#0-3) 

Once `verify_signature` succeeds, `WebhooksController#create` dispatches the entire raw body to the registered handlers: [5](#0-4) 

Every handler resolves the target repository/stack from a *different* field of the same body — `repository.full_name` — via `Handler#repository_name`/`#stacks`, and `Repository.from_github_repo_name` splits that string on `/` to find the `Repository` row: [6](#0-5) [7](#0-6) 

Nothing enforces that `repository.owner.login` (used to choose the verifying secret) matches the owner segment embedded in `repository.full_name` (used to select which `Repository`/`Stack` gets mutated). Handlers such as `PushHandler` (triggers `stack.sync_github`), `StatusHandler` (writes commit statuses), and `MembershipHandler`/pull-request handlers all key off `full_name`, not `repository_owner`: [8](#0-7) [9](#0-8) 

The binding that should hold is:
`organization whose secret authenticated the signature == organization that owns the repository the handler mutates`

but the engine only ever checks `verify(secret_for(repository_owner), raw_body) == true`; it never checks `repository_owner == full_name.split('/').first`. Because the repository config supports multiple independent GitHub Apps/organizations, each with its own `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml`, `github_app_config`/`github_organizations` in `lib/shipit.rb`), an attacker who legitimately controls one configured organization (i.e., knows/owns that org's `webhook_secret`, e.g. by owning a GitHub App installed on their own org that is one of the configured organizations) can sign an arbitrary raw body with their own secret while setting `repository.full_name` to point at a different, victim organization's repository. The signature check passes (it only validates against the attacker's own organization's secret), but the handler acts on the victim's `Repository`/`Stack`.

### Impact Explanation
This breaks the trust boundary "an organization that authenticated versus the repository that is written," matching the requested analog class. Concretely, with a `push` event the attacker can trigger `stack.sync_github(expected_head_sha:)` against a victim stack belonging to a different organization, and with `status`/`check_suite` events they can write fabricated CI status/check state onto the victim's commits — all cross-organization writes performed with attacker-controlled data despite a "valid" signature. This is a cross-repository/cross-organization write achieved without ever possessing the victim organization's `webhook_secret`, which fits the Critical-tier "cross-repository writes" impact bucket in the rules.

### Likelihood Explanation
This requires the deployment to be configured with more than one GitHub organization/app (the multi-org config schema shown in `test/dummy/config/secrets_double_github_app.yml` and supported by `github_app_config`/`github_organizations`), and the attacker must be an authorized principal for at least one of those configured organizations (i.e., they can generate a valid signature with that organization's own webhook secret — which they legitimately hold, e.g., as the admin of their own org's GitHub App). No repository write access, no Shipit session, and no other repo's secret is needed. In single-organization deployments (the common case, and the default schema) this issue is not reachable because there is only one secret to verify against and it always corresponds to the only configured org. The likelihood is therefore moderate and specific to multi-tenant/multi-org Shipit installations, which the engine explicitly documents and supports.

### Recommendation
After signature verification succeeds, cross-check that `repository_owner` (or `organization.login`) as used to select the verifying secret is exactly equal (case-insensitively) to the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request (422) otherwise. This closes the gap between "who signed" and "what gets mutated."

### Proof of Concept
Given a multi-org config like `test/dummy/config/secrets_double_github_app.yml` (organizations `Shopify` and `OrgTwo`, each with distinct `webhook_secret`s):

1. Attacker legitimately controls the GitHub App for `OrgTwo` and knows `OrgTwo`'s `webhook_secret`.
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "deadbeef",
     "repository": {
       "owner": { "login": "OrgTwo" },
       "full_name": "Shopify/shipit-engine"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `OrgTwo`'s known `webhook_secret` over the raw body and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgTwo"`, calls `Shipit.github(organization: "OrgTwo")`, and the signature verifies successfully (attacker used the correct secret for `OrgTwo`).
5. `PushHandler#process` resolves stacks via `Handler#repository_name` → `payload.dig('repository','full_name')` = `"Shopify/shipit-engine"`, an org the attacker does not control, and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim `Shopify` stack — a cross-organization write triggered with only the attacker's own org's webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```
