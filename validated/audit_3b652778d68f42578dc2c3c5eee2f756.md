This is confirmed: Shipit supports **multi-organization GitHub App configuration**, where each organization key in `secrets.github` has its own independent `webhook_secret` [1](#0-0) . The webhook signature-verification path and the repository-resolution path in the same request derive their organization/repository identifiers from **two different JSON fields inside the same attacker-controlled payload**, and nothing cross-checks that they agree.

### Title
Webhook signature verified against `repository.owner.login` while event is applied to `repository.full_name` — cross-organization webhook forgery (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [2](#0-1) [3](#0-2) . However, the actual handlers that act on the payload (e.g. `Shipit::Webhooks::Handlers::Handler#repository_name`, and every `PullRequest::*Handler#repository`) resolve the target repository from a **different** field: `payload.dig('repository', 'full_name')` [4](#0-3) [5](#0-4) . `Repository.from_github_repo_name` then splits `owner/name` from that string and looks up the record purely by string match, with no relation back to the value used for signature verification [6](#0-5) .

### Finding Description
The binding that should hold is:
`organization authenticated by signature (repository.owner.login)` == `organization whose repository/stack is mutated (repository.full_name's owner segment)`

These are two independently attacker-suppliable JSON strings within one HTTP body — GitHub does not cryptographically bind them together, and Shipit itself never compares them.

Sequence:
1. Shipit is configured with multiple organizations, each with its own `webhook_secret` in `secrets.github` [7](#0-6) . An attacker who administers/owns one such organization (`org-a`) — a value legitimately known to them, since they configured `org-a`'s GitHub App/webhook integration — knows `org-a`'s `webhook_secret`.
2. The attacker crafts a raw JSON body where `repository.owner.login = "org-a"` (or sets `organization.login = "org-a"`, since that's the fallback used in `repository_owner`) [3](#0-2) , but `repository.full_name = "victim-org/victim-repo"`.
3. The attacker computes `X-Hub-Signature` correctly using `org-a`'s known `webhook_secret` over the full raw body via `DeliverySigner`/HMAC-sha1 logic mirrored by `GitHubApp#verify_webhook_signature` [8](#0-7) .
4. `verify_signature` looks up `Shipit.github(organization: "org-a")`, verifies successfully (since it's `org-a`'s real secret), and the request passes [2](#0-1) .
5. `WebhooksController#create` dispatches the parsed body to all registered handlers for that event type [9](#0-8) .
6. Handlers such as `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc. resolve the repository via `Repository.from_github_repo_name(params.repository.full_name)` — i.e. `victim-org/victim-repo` — completely independent of the organization used for signature validation [10](#0-9) .
7. This lets the forged event trigger real side effects against `victim-org`'s stacks: creating/archiving Review Stacks, updating pull request state used for provisioning decisions (`provisioning_behavior_allow_all?`, label-driven archive/unarchive) [11](#0-10) , or forcing `review_stack.archive!` [12](#0-11) .

This is the direct analog of the reported bug class: a value is checked/consumed under one binding (`ownerBatches[from][i]` under index `i`) while the actual effect is applied to a different, unchecked binding (the swapped-in batch id) — here, the *authenticated* organization and the *acted-upon* organization/repository are two different fields never reconciled.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. An attacker controlling one legitimate low-privilege organization's webhook credentials can forge review-stack lifecycle events (archive/unarchive/provision) against any other organization/repository configured in the same Shipit instance, without ever having access to that victim organization's webhook secret or repository. This is a cross-organization write achieved purely through a payload-field mismatch, matching the High-impact category ("escalation ... unauthorized deploy/rollback" adjacent — here an unauthorized stack provisioning/archival action against a repository the attacker does not control).

### Likelihood Explanation
Requires the attacker to control at least one organization onboarded into the same multi-tenant Shipit deployment (a realistic scenario for a shared internal deploy platform serving many teams/orgs), and knowledge of only their own org's webhook secret — no access to the victim org is needed. The vulnerable code path (`repository_owner` vs `repository_name`) is hit on every webhook request and requires no additional preconditions beyond crafting a JSON body, well within an "unprivileged attacker relative to the victim org" threat model.

### Recommendation
After successfully verifying the signature for `repository_owner`, re-derive the acted-upon repository owner from `payload.dig('repository', 'full_name')` and assert it matches (case-insensitively) `repository_owner` before dispatching to handlers; reject the request (422) on mismatch. Alternatively, have `Handler#repository_name` consistently use the same organization value that was authenticated in `verify_signature`, rather than trusting an independent, unauthenticated-by-binding field from the payload body.

### Proof of Concept
```
POST /webhooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=<HMAC-SHA1 of raw body using org-a's known webhook_secret>

{
  "action": "opened",
  "number": 1,
  "pull_request": { ... valid nested fields ... },
  "repository": {
    "owner": { "login": "org-a" },      // used only for verify_signature's Shipit.github(organization:) lookup
    "full_name": "victim-org/victim-repo" // used by OpenedHandler#repository to find/act on the actual Repository
  },
  "sender": { "login": "attacker" }
}
```
`verify_signature` passes because the HMAC is valid for `org-a`'s secret; `PullRequest::OpenedHandler#repository` then resolves and acts on `victim-org/victim-repo`'s review stacks [10](#0-9) , demonstrating the cross-organization write.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
