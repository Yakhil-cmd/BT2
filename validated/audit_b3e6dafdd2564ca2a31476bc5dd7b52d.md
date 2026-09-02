### Title
Webhook signature verification keys on `repository.owner.login` while handlers act on `repository.full_name` from the same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to authenticate a webhook based on the attacker-controlled `repository.owner.login` field in the JSON body, but the event handlers that subsequently act on the request use a different field, `repository.full_name`, from that same unverified body to decide which `Stack`/`Repository` to operate on. Nothing binds these two fields together.

### Finding Description
`verify_signature` computes which `GitHubApp` (and therefore which `webhook_secret`) to use for HMAC verification purely from the payload itself, before the signature has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (used when Shipit is configured with multiple GitHub Apps, one per organization, as documented in `docs/setup.md`): [3](#0-2) 

Meanwhile, every webhook handler (`Handler#stacks` / `#repository_name`) resolves the target `Repository`/`Stack` using a *different* field from the same JSON body, `repository.full_name`, which is never cross-checked against `repository.owner.login`: [4](#0-3) [5](#0-4) 

Because both `owner.login` and `full_name` are attacker-supplied JSON keys inside the same top-level `repository` object with no cross-validation, an attacker who is able to produce a valid signature for **any one** configured organization (e.g., because they administer/own that org's Shipit installation and know its `webhook_secret`, or because that org's `webhook_secret` is left blank — an explicitly supported/documented configuration per `docs/setup.md`) can submit a payload where `repository.owner.login` matches the org whose secret they control (satisfying `verify_webhook_signature`), while `repository.full_name` names a completely different, more privileged repository/stack: [6](#0-5) 

The equality that should hold — "organization whose signature authenticated the request" == "repository the handlers are permitted to act on" — is broken: verification authenticates the org identified by `owner.login`, but the mutation targets the repository identified by `full_name`, an independent, unauthenticated field.

### Impact Explanation
This lets an attacker who controls (or knows the secret of) one configured GitHub organization forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are processed as though they originated from an unrelated repository/organization. Depending on handler and stack configuration, this can:
- Trigger `GithubSyncJob`/`sync_github` against another organization's stack, and where `continuous_deployment` is enabled, indirectly trigger an unauthorized deploy pipeline on push events for a repository the attacker does not control.
- Inject forged commit `status`/`check_suite` results for a targeted stack, bypassing CI gating used by the merge queue and deploy safety checks.
- Create/modify `Team`/`Membership` records tied to `Shipit.github_teams` authorization via the `membership` handler, escalating into the app's authorization model.

This falls into the report's High/Critical bands: escalation into `Shipit.github_teams` authorization, or an unauthorized deploy, depending on which handler/stack is targeted.

### Likelihood Explanation
Requires the attacker to already control (or know the webhook secret of) at least one organization configured in the Shipit instance — a realistic scenario for multi-tenant/multi-org Shipit deployments (explicitly documented and supported) where different teams manage different GitHub Apps feeding the same Shipit instance, or for a single-org deployment where `webhook_secret` is left unset (also explicitly documented as optional). No GitHub write access, `ApiClient` token, or Shipit session is required — only the ability to POST to `/webhooks` with a crafted body and a valid `X-Hub-Signature` for the organization the attacker controls.

### Recommendation
After successfully verifying the signature for the organization identified by `repository.owner.login` (or `organization.login`), require that the same organization/owner is what handlers use to resolve the target `Repository`. Concretely: derive `repository_name`/stack lookup consistently from the same, already-authenticated owner value used in `verify_signature`, and reject the webhook (422) if `repository.owner.login` does not match the owner portion of `repository.full_name`. Alternatively, look up the `Repository` first, derive `organization` from the persisted `Repository#owner`, and use that to select the verification key, rather than trusting payload-level `owner.login` independently from `full_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled installation, known `webhook_secret`) and `OrgB` (victim, stack `OrgB/critical-repo` with `continuous_deployment: true`), as in the documented multi-org config (`docs/setup.md` "Using Multiple GitHub Applications").
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha claimed to exist in OrgB/critical-repo>",
  "repository": {
    "full_name": "OrgB/critical-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s known `webhook_secret` over the raw body and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature (since it's genuinely signed with `OrgA`'s secret).
5. `Webhooks::Handlers::PushHandler#process` resolves the target via `Repository.from_github_repo_name("OrgB/critical-repo")`, matches the `not_archived` stack on branch `main`, and calls `stack.sync_github(expected_head_sha: ...)`, driving `OrgB`'s stack state/CI/CD pipeline using a webhook that was never authenticated by `OrgB`.

### Citations

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
