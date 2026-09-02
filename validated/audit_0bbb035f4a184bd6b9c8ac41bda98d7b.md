### Title
Webhook signature verification keys off attacker-controlled `repository.owner.login`, letting an org with a known secret forge events for another org's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-tenant GitHub App configuration, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the unverified, attacker-controlled JSON body, before the signature check happens. Every downstream webhook handler, however, resolves the actual `Repository`/`Stack` to act on from a different field of the very same unverified body: `repository.full_name`. Because the field used to pick the verifying secret and the field used to pick the affected repository are never bound to each other by the signature, a party who legitimately possesses the `webhook_secret` for one configured organization can forge a payload whose `repository.owner.login` names their own organization (so verification passes with their own secret) while `repository.full_name` names a repository belonging to a completely different onboarded organization.

### Finding Description
`repository_owner` is computed purely from the JSON body: [1](#0-0) 

That value selects the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) via `Shipit.github(organization: repository_owner)`: [2](#0-1) 

`Shipit.github` maps the organization name to a per-org config entry containing its own `webhook_secret`: [3](#0-2) 

Only *after* this before_action passes does `create` dispatch the same, now-"verified" raw payload to every registered handler for the event: [4](#0-3) 

Every base handler resolves the target `Stack`/`Repository` from `repository.full_name`, a field that was never part of what the signature check bound to the secret it used: [5](#0-4) 

`PushHandler`, for example, then acts on whatever stacks match that resolved repository/branch: [6](#0-5) 

The equality that should hold is: `organization whose secret authenticated the request == organization that owns the repository the handlers act on`. Before an attack, for legitimate GitHub-originated webhooks these two are always the same because GitHub signs the payload it itself generates. After the attack, an attacker who knows (or controls) the `webhook_secret` configured for organization A crafts a body where `repository.owner.login`/`organization.login` = `"orgA"` but `repository.full_name` = `"orgB/target-repo"`, signs the raw body with `orgA`'s secret, and posts it. `verify_signature` computes `Shipit.github(organization: "orgA")`, verifies successfully against `orgA`'s secret, and the request proceeds to handlers that instead operate on `orgB`'s stack — a repository the attacker's secret was never meant to authorize.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credential authenticated the webhook" and "the repository whose state is mutated," matching the required analog class. Concretely, this can drive:
- `MembershipHandler`-mediated creation/removal of `Team`/`Membership` records for `orgB`'s GitHub teams (escalation into `Shipit.github_teams` authorization) since membership webhooks are processed the same way, keyed off body content resolved after the organization-scoped signature check passes: [7](#0-6) 
- Forged `push`/`status`/`pull_request` events causing `Stack#sync_github`, review-stack archive/unarchive/provisioning, or PR-state mutations against a stack owned by an organization the attacker has no legitimate relationship to: [6](#0-5) 

This qualifies as High severity: escalation into `Shipit.github_teams` authorization and unauthorized mutation of another organization's stack state, satisfying the "organization authenticated versus the repository written" binding-break criterion.

### Likelihood Explanation
This is only exploitable on a multi-tenant Shipit deployment where more than one GitHub organization is configured under `secrets.github` (`github_app_config`), each with its own `webhook_secret`, and where the attacker legitimately possesses (or can obtain, e.g. as an admin of their own onboarded org) the `webhook_secret` for at least one of those configured organizations. No GitHub App private key, session, or `ApiClient` token is required — only knowledge of one tenant's webhook secret plus the ability to POST directly to the `/webhooks` endpoint, which is unauthenticated by design (webhook signature is the only gate). This is a realistic configuration for SaaS-style Shipit deployments serving multiple orgs.

### Recommendation
Bind the field used to select the verifying secret to the same field handlers use to resolve the affected repository, or verify the payload against every configured organization's secret and require that the matching organization also own `repository.full_name`. Concretely, in `WebhooksController#verify_signature`, after determining `verified`, additionally assert that `repository_owner` matches the owner segment of `params.dig('repository', 'full_name')` (and reject with 422 if they diverge) before allowing the request to reach `Shipit::Webhooks.for_event`.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, `orgA` (attacker-known secret `secretA`) and `orgB` (victim org, onboarded stack `orgB/victim-repo`).
2. Attacker crafts a `push` JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(secretA, raw_body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and verifies successfully using `secretA` [2](#0-1) .
5. `create` dispatches to `PushHandler`, which resolves the target stack from `repository.full_name = "orgB/victim-repo"` [5](#0-4)  and triggers `stack.sync_github` on `orgB`'s stack despite the request only ever being authenticated against `orgA`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-1)
```ruby
# frozen_string_literal: true
```
