### Title
Webhook signature verification key is selected by an attacker-controlled field that is not the field handlers act on, allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks the `GitHubApp` (and thus the webhook secret) used to validate the request's HMAC signature based on `repository_owner`, which is parsed out of the *unauthenticated* JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). Once the signature check passes, the exact same untrusted body is handed to event handlers (`Shipit::Webhooks::Handlers::Handler`), which determine which `Repository`/`Stack` record to mutate using a *different* field of the same body: `payload.dig('repository', 'full_name')`. Because the field used to select the verification key (`repository.owner.login`) and the field used to select the object being written to (`repository.full_name`) are independent, attacker-controlled values inside the same JSON blob, an attacker who legitimately controls the webhook secret for one organization configured in this Shipit instance can forge a validly-signed webhook whose `repository.full_name` points at a completely different organization/repository's stack.

### Finding Description
`Shipit.github(organization: repository_owner)` resolves the `GitHubApp` config (and its `webhook_secret`) purely from the `repository.owner.login` (or `organization.login`) key of the raw, not-yet-verified JSON payload: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then only checks that the HMAC-SHA1 of the raw body matches under *that* secret: [3](#0-2) 

Shipit supports hosting multiple GitHub organizations in one instance, each with its own app/webhook configuration, selected by `github_app_config(organization)`: [4](#0-3) 

After the signature check passes, `WebhooksController#create` parses the raw body again and dispatches it unmodified to handlers: [5](#0-4) 

Every handler resolves the target `Repository`/`Stack` from `repository.full_name` in that same payload — a field that was never part of the trust decision made in `verify_signature`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

Equality that should hold but does not:
`organization whose webhook_secret authenticated the request == organization that owns the repository/stack the handler mutates`

Concretely, an attacker who legitimately administers (or has push access to) their own GitHub organization "attacker-org" — which is one of the organizations configured in `secrets.github` for this multi-tenant Shipit instance, and for which they can therefore obtain a valid `X-Hub-Signature` (either because they configured the webhook secret themselves, or because they can trigger genuine webhook deliveries from GitHub for their own org and replay/modify the JSON body before the app parses it a second time) — can send a POST to `/webhooks` where:
- `repository.owner.login` = `"attacker-org"` (drives secret selection, verification passes)
- `repository.full_name` = `"victim-org/victim-repo"` (drives which `Stack`/`Commit` gets mutated)

Because `create` re-parses `request.raw_post` independently of what `verify_signature` inspected, and no handler cross-checks `repository.owner.login` against `repository.full_name`, the forged event is accepted as authentic for the victim's stack.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding explicitly called out as an in-scope class. Exploitable handlers include:
- `StatusHandler` — forging a `success` CI status for an arbitrary commit SHA on a victim stack, which can satisfy `ci.require` gating and enable an unauthorized deploy/merge through the merge queue.
- `PushHandler` — triggering `sync_github` with an attacker-chosen `expected_head_sha` for a victim stack/branch.
- Pull-request handlers (`opened_handler.rb`, `labeled_handler.rb`, `closed_handler.rb`, etc.) — creating, archiving, unarchiving, or provisioning review stacks belonging to a victim repository.

This constitutes cross-organization/cross-repository writes and can escalate to an unauthorized deploy/merge, matching the Critical impact bucket defined by the rules.

### Likelihood Explanation
The prerequisite is that the deployment hosts multiple organizations with independent webhook secrets (a supported, documented configuration path via `secrets.github` keyed by organization — see `github_app_config`/`github_organizations` in `lib/shipit.rb`). In that configuration, any org onboarded to the shared Shipit instance — even one with no relationship to the victim org — is sufficient to forge cross-repository events; no privileged Shipit account, API token, or GitHub App private key is required, only a webhook secret for one's own tenant organization.

### Recommendation
Bind the field used to select the verification key to the field used to identify the target object. Concretely:
- After computing `repository_owner` for `Shipit.github(organization:)`, verify that `params.dig('repository', 'full_name')` (or `params.dig('organization', 'login')` for org-scoped events) is actually owned by that same `repository_owner` before dispatching to handlers, rejecting (422) any mismatch.
- Alternatively, resolve the target `Repository`/organization first from `repository.full_name`, and use the owner of *that* resolved repository (not the raw payload field) to select the webhook secret used for verification.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations in `secrets.github`, e.g. `attacker-org` and `victim-org`, each with its own `webhook_secret`.
2. As an attacker who legitimately administers `attacker-org` and thus knows/controls its `webhook_secret`, craft a `status` webhook payload:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org_webhook_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` from `repository.owner.login`, verifies successfully against the attacker's own secret.
5. `create` re-parses the same body and `StatusHandler` (via `Repository.from_github_repo_name("victim-org/victim-repo")`) creates a fabricated successful CI status on the victim's commit — despite the request never being signed by `victim-org`'s webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
