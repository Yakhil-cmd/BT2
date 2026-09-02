### Title
Webhook signature verified against payload-supplied organization while handlers act on a payload-supplied repository, letting one organization's webhook credentials forge writes into another organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC verification based on `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')`), and then, once "verified," hands the *entire* raw payload to `Shipit::Webhooks::Handlers::Handler` subclasses, which independently resolve the target `Stack`/`Repository` using a different field of the same untrusted payload (`repository.full_name`). Nothing enforces that the organization whose secret validated the signature matches the repository the handlers actually mutate.

### Finding Description
`verify_signature` computes the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `secrets.github` (multi-app configuration, documented in `docs/setup.md`), and `verify_webhook_signature` just HMAC-compares against that specific secret: [3](#0-2) 

Once the signature check passes (using the secret belonging to `repository.owner.login`), the raw, still-attacker-controlled `params` hash is dispatched unmodified to every registered handler for the event: [4](#0-3) 

Handlers never re-check `repository.owner.login`; they resolve the actual `Repository`/`Stack` from a *different* field, `repository.full_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

Because `owner.login` (used to pick the signing secret) and `full_name` (used to pick the mutated repository) are two independent JSON fields with no cross-validation, an attacker who legitimately controls one organization configured in Shipit's multi-org secrets (`docs/setup.md` "Using Multiple Github Applications") — and therefore can produce a validly-signed webhook body under their own `webhook_secret` — can set `repository.owner.login` to their own org (so the correct, known secret is selected and the HMAC check passes) while setting `repository.full_name` to `"other-org/other-repo"`. The request will pass `verify_signature` and then be processed by handlers as if it genuinely originated for the other organization's repository/stack.

This is the same bug class as the referenced report: a check is bound to one entity (`address(this)` instead of `msg.sender` in the Sherlock finding) while the actual state-changing action targets a different entity supplied by the caller — here, the *authenticating organization* (`repository.owner.login`) versus the *repository actually written* (`repository.full_name`).

### Impact Explanation
Handlers acting on `full_name` perform real, state-changing writes on `Stack`/`Repository`/`Task` records: `PushHandler` triggers `stack.sync_github`, which can advance `expected_head_sha` and drive deploy scheduling for `not_archived` stacks matching the branch; `ClosedHandler`/other `PullRequest` handlers archive review stacks. Since these writes are scoped by `Repository.from_github_repo_name(params.repository.full_name)` and not by the authenticated organization, an attacker owning one configured organization's GitHub App credentials can inject forged, validly-"signed" webhook events that mutate stacks belonging to any other organization hosted in the same Shipit instance — a cross-repository/cross-organization write achieved without any authorization over the targeted organization or repository.

### Likelihood Explanation
Exploitation requires the attacker to control (or have configured) at least one organization's `webhook_secret` in a Shipit deployment that hosts multiple organizations — a scenario explicitly supported and documented (`docs/setup.md`, "Using Multiple Github Applications"). No GitHub App installation, repository write access, or Shipit session is needed for the *target* organization; only knowledge of one's own already-configured secret, which every onboarded organization in a multi-tenant Shipit install possesses. This is a straightforward HTTP POST with a crafted JSON body and a correctly computed HMAC using that known secret.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after verifying the signature, cross-check that the repository/organization actually referenced by the payload's other fields (e.g. `full_name`'s owner segment, or `organization.login` used elsewhere) matches the organization whose secret validated the request, and reject the webhook otherwise. Handlers should not trust `repository.full_name` alone to select the mutated `Stack`; the resolved `Repository`'s owner should be reconciled against the authenticated organization before any handler runs.

### Proof of Concept
1. Shipit is configured with multiple GitHub organizations per `docs/setup.md`, e.g. `attacker-org` and `victim-org`, each with its own `webhook_secret`.
2. Attacker knows `attacker-org`'s `webhook_secret` (they configured/own that org's GitHub App).
3. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)`.
5. `WebhooksController#verify_signature` reads `repository_owner` = `"attacker-org"`, calls `Shipit.github(organization: "attacker-org")`, and the HMAC check passes because the attacker signed with the correct secret for that organization.
6. `Shipit::Webhooks.for_event('push')` handlers run with the unmodified payload; `PushHandler#stacks` (via `Handler#repository_name`) resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on stacks belonging to `victim-org`, despite the attacker having no relationship to that organization or repository.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
