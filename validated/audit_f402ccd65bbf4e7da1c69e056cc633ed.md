### Title
Webhook Signature Verification Keyed on `repository.owner.login`, but Event Processing Routes on `repository.full_name` — Cross-Organization Webhook Spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments (`secrets.github` configured with multiple org entries), the webhook signature is verified using a `GithubApp` instance selected by `repository_owner` (derived from `repository.owner.login`/`organization.login`), but the event handlers that actually mutate application state select the target `Repository`/`Stack` using a *different* payload field, `repository.full_name`. This breaks the binding: "organization authenticated == repository that is written." An admin of one onboarded GitHub organization (who legitimately knows that organization's own `webhook_secret`) can forge a validly-signed webhook whose `repository.owner.login` matches their own org (so their own secret verifies), while `repository.full_name` names a repository/stack belonging to a *different* onboarded organization.

### Finding Description
`WebhooksController#verify_signature` selects the verifying `GithubApp`/secret using only the owner login found in the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config/secret keyed by exactly that owner string: [3](#0-2) 

The signature itself is only an HMAC over the raw JSON body using the secret associated with `repository_owner`; it proves the payload was signed by *some* org's configured secret, not that the org whose secret matched is the actual owner of the repository referenced elsewhere in the same payload.

Once the signature passes, `Webhooks.for_event(event)` handlers run and independently resolve the target repository/stack using `repository.full_name`, a field that is not cross-checked against `repository.owner.login`: [4](#0-3) [5](#0-4) 

Because nothing enforces `repository.full_name.split('/').first == repository.owner.login` (or `organization.login`), an attacker who administers Org A's GitHub organization webhook configuration (and therefore legitimately possesses Org A's `webhook_secret`, since they configured it when wiring the webhook into Shipit) can sign an arbitrary JSON body with Org A's secret while setting `repository.owner.login` to `"orgA"` and `repository.full_name` to `"orgB/some-repo"`. `verify_signature` picks Org A's `GithubApp`, verifies successfully, and the request proceeds; the downstream handler then resolves and acts on Org B's `Repository`/`Stack` via `full_name`.

This is the direct analog of the reported bug class: a field consumed for authorization/verification purposes (`repository.owner.login`, used to pick the signing key) is disjoint from the field actually acted upon (`repository.full_name`, used to select the mutated resource), exactly as the SPL/period mismatch in the audited contracts let a stale, unchecked value drive downstream state changes.

### Impact Explanation
This crosses an organization boundary that Shipit's multi-tenant GitHub App model is explicitly designed to keep separate — each organization is only supposed to be able to authenticate and affect its own repositories/stacks. Concretely, an Org A insider can forge signed `status`, `check_suite`, `push`, `pull_request`, or `membership` events for Org B's stacks:
- `status`/`check_suite` handlers affect commit deployability/CI-gating state used by `Stack#trigger_deploy` and undeployed-commit checks, which can enable an unauthorized deploy on a stack the attacker has no legitimate access to.
- `membership` handlers create/delete `Team`/`Membership` records cross-organization, corrupting `Shipit.github_teams`-based authorization state for another org.
- `push` handlers can inject/alter commit records tracked by another organization's stack.

This matches the "High/Critical" bar: escalation into another organization's stack state and authorization records, and a path toward unauthorized deploys, via a webhook whose only defense (HMAC signature) is satisfiable by an unrelated organization.

### Likelihood Explanation
Requires the Shipit deployment to be configured with more than one GitHub organization (`secrets.github` with multiple org keys, the schema `Shipit.github_default_organization` supports) — this is a supported, documented configuration, not a misuse of the engine. Any legitimate admin of one of those organizations (who has ordinary, unprivileged access to that org's own webhook settings, not to Shipit itself) can mount the attack purely by crafting an HTTP POST to Shipit's public `/github_hooks` endpoint; no Shipit session, `ApiClient` token, or repository-write access to the victim org is needed.

### Recommendation
After `verify_signature` succeeds, enforce that the organization used to select the verifying secret matches the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, have `Handler#repository_name`/`Repository.from_github_repo_name` cross-validate against the verified `repository_owner` used during signature verification, so a single canonical, signature-bound field determines both which secret verifies the payload and which repository/stack is mutated.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orga` (secret `S_A`, controlled/known by the attacker who administers Org A's GitHub webhook settings) and `orgb` (secret `S_B`, unknown to the attacker), each with a stack, e.g. `orgb/victim-repo`.
2. Attacker crafts payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)` and sends `POST /github_hooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` computes `repository_owner = "orga"`, calls `Shipit.github(organization: "orga")`, verifies the HMAC with `S_A` — success — request proceeds. [6](#0-5) 
5. `Webhooks.for_event('status')` handler resolves target via `payload.dig('repository', 'full_name')` = `"orgb/victim-repo"`, finds Org B's `Repository`/`Stack`, and applies the forged CI status, affecting Org B's stack despite the signature having been verified against Org A's secret. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
