### Title
Cross-organization webhook forgery via mismatched signature-selection and repository-lookup fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify a request against based on `repository.owner.login` (or `organization.login`) taken from the *unauthenticated* JSON body, but the event handlers that actually act on the request identify the target repository/stack using a *different* field from the same body: `repository.full_name`. In a multi-organization Shipit deployment (each org has its own `webhook_secret`, as documented in `docs/setup.md` and `config/secrets.development.example.yml`), an actor who legitimately controls one organization's webhook secret can forge a payload where the "owner" field used for signature verification points to their own org, while the "full_name" field used for the actual repository/stack lookup points to a victim organization's repository.

### Finding Description
The controller resolves the signing secret like this: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `params.dig('repository', 'owner', 'login')` (or `organization.login`), and is used to pick a `GitHubApp` instance with its own `webhook_secret`: [3](#0-2) [4](#0-3) 

Once `verify_webhook_signature` succeeds (HMAC-SHA1 of the *entire raw body* against the secret selected by the attacker-controlled `owner.login`/`organization.login` field), the entire raw JSON body — including any other field — is dispatched unfiltered to the registered handlers: [5](#0-4) 

Handlers, however, identify the target repository using a *different* field, `repository.full_name`, not the `owner.login`/`organization.login` field used for secret selection: [6](#0-5) [7](#0-6) 

So the equality that the design implicitly assumes but never enforces is:
`organization whose secret verified the signature == organization that owns the repository the handler will act on`

Because both `repository.owner.login` and `repository.full_name` are ordinary JSON fields inside the same signed payload, an attacker fully controls both. They can set `repository.owner.login = "attacker-org"` (an org they have legitimately been given a `webhook_secret` for, per the documented multi-org setup in `docs/setup.md` and `config/secrets.development.example.yml`) while setting `repository.full_name = "victim-org/victim-repo"`, then compute the HMAC over the whole payload using their own `attacker-org` secret and POST it directly to `/webhooks` (this endpoint accepts any HTTP POST — it is not otherwise bound to actual GitHub traffic). `verify_signature` looks up the org via the forged `owner.login`, correctly verifies the signature against the attacker's own secret, and passes. The dispatched handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `pull_request/*` handlers, etc.) then reads `repository.full_name` to resolve the actual `Repository`/`Stack`, which belongs to the victim organization, and acts on it.

This is the direct structural analog of the `cancelOrder` bug: `cancelOrder` records `cancelled[orderHash]` based on caller identity but never re-verifies that the "order" acted upon in `matchOrders*` corresponds to a party who actually authorized it via signature — likewise here, the webhook signature check verifies *a* signature belongs to *some* org, but never re-verifies that the org whose key validated the signature is the same org as the repository being mutated.

### Impact Explanation
This breaks the cross-tenant trust boundary that a shared multi-organization Shipit instance depends on: any organization onboarded onto the instance (with its own `webhook_secret`) can forge webhook events that:
- Trigger `stack.sync_github(expected_head_sha:)` for a victim org's stacks via `PushHandler` [8](#0-7) , forcing unauthorized synchronization of a specific attacker-chosen commit SHA as the "expected head" for a victim repository.
- Inject forged commit statuses for a victim's commits via `StatusHandler#process` / `Commit#create_status_from_github!` [9](#0-8) , which can manipulate CI/status gating that Shipit deploy flows rely on.
- Archive/unarchive victim review stacks or update victim pull request metadata via the `pull_request/*` handlers, all of which key off `params.repository.full_name` [10](#0-9) .

This is a cross-repository write into another organization's Shipit-managed state, performed by an entity that only possesses credentials scoped to its own organization — matching the "cross-repository writes" / "unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitability requires (a) the Shipit instance to be configured with the documented multi-organization `github:` schema (explicitly supported and documented), and (b) attacker possession of any one participating organization's `webhook_secret` (which that organization's own administrators legitimately hold, since they created their own GitHub App and secret per `docs/setup.md`). No GitHub-side compromise, no Shipit session, and no privileged Shipit account are required — the attacker only needs to be able to compute an HMAC and POST directly to the public `/webhooks` endpoint, which is not otherwise authenticated as coming from GitHub.

### Recommendation
After selecting the GitHub App/secret and verifying the signature, re-derive and cross-check that the organization used for signature/secret selection matches the organization actually referenced by the fields the handlers will act on (e.g., verify that `repository.full_name`'s owner segment equals the verified `repository_owner`/`organization.login`, and reject the webhook otherwise). Alternatively, look up the target `Repository`/`Stack` from the trusted, already-verified organization identity rather than trusting a separate unauthenticated field embedded in the payload.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (webhook_secret `S_A`, known to the attacker who administers that org's GitHub App) and `victim-org` (webhook_secret `S_V`, unknown to attacker), per the documented multi-org `github:` config.
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_A, raw_body)`.
4. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and the above body/signature.
5. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and `verify_webhook_signature` succeeds because it was signed with `S_A`.
6. `PushHandler#process` resolves the repository via `params.repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack — a cross-organization write the attacker's own credentials should never have authorized.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
