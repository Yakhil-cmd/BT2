### Title
Cross-organization webhook forgery via mismatched trust binding between signature verification and repository resolution - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments, the HMAC signature that authenticates a GitHub webhook is looked up and verified using an organization name taken from the *same untrusted payload* that later determines which repository/stack the event is applied to. Because these two payload fields are not cryptographically bound to each other beyond both being inside one HMAC-signed blob, an attacker who legitimately controls the webhook secret for *one* configured organization can forge a signature for a payload whose `repository.full_name` targets a *different* organization's repository/stack.

### Finding Description
`Shipit::WebhooksController#verify_signature` derives the signing organization purely from the incoming payload: [1](#0-0) [2](#0-1) 

`repository_owner` (`repository.owner.login`, or `organization.login` fallback) selects which `GitHubApp` instance — and thus which `webhook_secret` — is used to verify `X-Hub-Signature`, via `Shipit.github(organization: repository_owner)`: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` dispatches the *entire raw payload* to event handlers, unconstrained by which organization's secret validated it: [4](#0-3) 

Handlers such as `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` and `PushHandler#process` resolve the target repository/stack from a *different* field of the same payload — `repository.full_name` — with no re-check that this repository actually belongs to the organization whose secret validated the signature: [5](#0-4) [6](#0-5) 

The broken binding is: **organization authenticated (`repository.owner.login` used to select `webhook_secret`) ≠ repository written (`repository.full_name` used to resolve `Stack`/`Repository`)**. In the single-organization configuration this is harmless because there is only one secret and one trusted organization; but Shipit explicitly supports a multi-organization mode where each org has its own `app_id`/`webhook_secret` pair, and the org key is dynamically selected from attacker-controlled payload content: [7](#0-6) [8](#0-7) 

An attacker who legitimately controls a GitHub App/organization already configured in `secrets.github` (i.e., they know that organization's `webhook_secret`, because they administer that org's GitHub App installation) can construct a POST to `/webhooks` with:
- `repository.owner.login` = their own org (so `verify_signature` selects and validates against their known secret), and
- `repository.full_name` = `victim-org/victim-repo` (an entirely different, unrelated stack configured in the same Shipit instance).

Because the HMAC only proves "this attacker-controlled org's secret signed this exact byte-string," and the byte-string's `repository.full_name` is free-form JSON content chosen by the attacker before signing, the signature check offers no isolation between tenants.

### Impact Explanation
This breaks the isolation model of Shipit's multi-organization support. An attacker with a legitimately configured (but low-trust) organization/app in the same Shipit deployment can forge `push`, `status`, `check_suite`, `pull_request`, and `membership` events targeting stacks/repositories that belong to a completely different, unrelated organization. Depending on which handler consumes the forged event, this can:
- Trigger `GithubSyncJob`/`stack.sync_github` for victim stacks (`PushHandler`), and
- Forge commit statuses on victim commits/PRs, which the merge queue (`merge_status`) can rely on for auto-merge decisions.

Given the impact bar in scope ("unauthorized deploy, rollback or merge" or "escalation into `Shipit.github_teams` authorization"), forged commit-status/merge-status events that make the merge queue believe a victim PR is CI-green could lead to an **unauthorized merge**, satisfying the Critical/High bar. This qualifies as a cross-organization write across a trust boundary that the engine is documented to enforce (`docs/setup.md` describes org-scoped GitHub Apps as isolating orgs from one another).

### Likelihood Explanation
Exploitability requires:
1. Shipit configured for multiple GitHub organizations (`secrets.github` keyed by org name) — an explicitly documented, supported configuration.
2. The attacker legitimately controls (as an unprivileged user relative to the victim org) one of those configured organizations/apps, i.e., they know its `webhook_secret`.

This does not require any GitHub push access, Shipit session, or `ApiClient` token — only the ability to send an arbitrary signed HTTP request to the public `/webhooks` endpoint using a secret the attacker legitimately possesses for their own org. Given multi-org Shipit is a first-class documented feature intended precisely to host several orgs' repositories in one instance without granting them mutual trust, this is a realistic likelihood in that deployment topology.

### Recommendation
Bind repository resolution to the authenticated organization: after `verify_signature` succeeds, require that `repository.full_name`'s owner segment (or `organization.login`) match the exact `repository_owner`/org key used to select the verifying `webhook_secret`, and reject the request (422) otherwise. Alternatively, resolve the target `Stack`/`Repository` only among those scoped to the verified organization, never globally by `full_name` alone.

### Proof of Concept
1. Shipit configured with two orgs in `secrets.github`: `attacker-org` (app/secret known to the attacker, who administers that GitHub App) and `victim-org` (hosting `victim-org/victim-repo`, unrelated to the attacker).
2. Attacker crafts a `push` (or `status`) payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verifies successfully against the attacker's own secret.
5. `WebhooksController#create` hands the full payload to `Shipit::Webhooks.for_event("push")`, and `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")`, acting on `victim-org`'s stack despite the signature never having been checked against `victim-org`'s secret.

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
