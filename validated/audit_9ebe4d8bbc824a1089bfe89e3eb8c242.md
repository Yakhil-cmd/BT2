This confirms `Shipit.github(organization:)` supports **multi-organization** configuration keyed by organization name (`github_app_config`), each with its own independent `webhook_secret`. This makes the signature-verification-vs-processing mismatch concretely exploitable.

### Title
Webhook Organization-Verified Signature Does Not Bind to the Repository Acted Upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook using the `webhook_secret` belonging to the organization derived from `repository.owner.login` (or the `organization.login` fallback), while the actual event-processing code (`Handler#repository_name` / `Repository.from_github_repo_name`) resolves the repository/stack to act on from the independent `repository.full_name` field. Because these two fields are never cross-validated against each other, an event that is validly signed for organization A can carry a `repository.full_name` pointing at organization B's repository, letting the payload's cryptographically-verified identity diverge from the repository whose state is mutated.

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and looks up the corresponding `GitHubApp` config/secret via `Shipit.github(organization: repository_owner)`: [1](#0-0) [2](#0-1) 

`Shipit.github` supports multiple independently-configured organizations, each with its own `webhook_secret`, keyed by organization name: [3](#0-2) 

Once the signature check passes, the raw JSON payload is dispatched unmodified to the registered handler, e.g. `PushHandler`: [4](#0-3) 

Every handler resolves which `Repository`/`Stack` to mutate using a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name`, completely independent of the `repository.owner.login` value used for signature verification: [5](#0-4) [6](#0-5) 

Because HMAC signing covers only the raw request body (verified against the org resolved from `owner.login`) and not a binding between "the org whose secret validated this request" and "the repository the handler will operate on" (`full_name`), the two fields can be made inconsistent by anyone able to produce a validly-signed payload for *any one* organization configured in Shipit (e.g., their own org, for which they legitimately control push/webhook events and thus the exact JSON body sent to Shipit's `/webhooks` endpoint). `PushHandler` in particular executes `stack.sync_github(expected_head_sha: params.after)` purely based on the `repository.full_name`-derived stack: [7](#0-6) 

This is the structural analog of the CometBFT report: an equality that the code implicitly assumes — `organization_that_authenticated == organization_of_repository_being_written` — is never actually enforced; the two are derived from independently-controllable payload fields.

### Impact Explanation
If exploitable, this would let an attacker who controls (or can fabricate/replay) a correctly-signed webhook for organization A cause Shipit to sync/deploy state for a repository/stack under organization B, i.e. cross-organization/cross-repository writes triggered without B's cooperation — matching the "cross-repository writes" Critical impact category.

### Likelihood Explanation
This requires: (1) Shipit configured with multiple organizations (`github_organizations` > 1, a documented supported mode), and (2) attacker control over a raw JSON body that is validly HMAC-signed by one configured org's `webhook_secret` while its `repository.full_name` names a stack belonging to a different configured org. GitHub itself always sends internally consistent payloads (owner and full_name match), so an unprivileged external attacker cannot simply relay a genuine GitHub webhook to trigger this — they would need either control of a legitimate webhook sender for org A that can be coerced into emitting a crafted body, or another mechanism to get org A's signature over an attacker-chosen body. I could not verify within this codebase whether any component allows an attacker to freely choose the raw body signed by a given org's secret (e.g. a replay/relay primitive); the `test/controllers/webhooks_controller_test.rb` and fixtures show GitHub-authentic payloads are always self-consistent. Given this uncertainty about a concrete attacker-controlled forgery path for the signed body, likelihood is not conclusively demonstrated from static analysis alone.

### Recommendation
Bind the signature-verified organization to the repository being acted upon: after resolving `repository_owner` and verifying the signature, re-derive `repository.full_name`'s owner and reject the request (422) if it does not match `repository_owner`/the verified organization, in `WebhooksController#verify_signature` and/or centrally in `Handler#repository_name`.

### Proof of Concept
Not constructed — a concrete PoC requires demonstrating that an attacker can obtain an HMAC-valid signature (per one org's `webhook_secret`) over a JSON body whose `repository.full_name` names a different org's tracked repository. This engine's own code does not provide such a forgery primitive, so root cause is present but full exploitability across an authentication boundary is unconfirmed with the available context.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-39)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
end
```
