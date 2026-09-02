### Title
Cross-organization webhook forgery via `repository_owner`/`repository.full_name` mismatch enables unauthorized sync/deploy of a stack belonging to a different GitHub organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` configured with several GitHub orgs, each with its own `app_id`/`webhook_secret`), the webhook signature is verified against the secret of the organization named in `repository.owner.login` (or `organization.login`), while the actual repository/stack that gets acted upon is selected using an entirely different payload field, `repository.full_name`. An administrator who legitimately controls one org's GitHub App (and therefore legitimately knows that org's `webhook_secret`) can forge a webhook whose `repository.owner.login` matches their own org (so it passes HMAC verification) but whose `repository.full_name` points at a repository belonging to a *different* organization tracked by the same Shipit instance. This breaks the equality "organization that authenticated == repository that is written," letting one tenant trigger sync/deploy-adjacent actions on another tenant's stacks.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which secret) to verify the HMAC signature against using `repository_owner`, computed from the payload: [1](#0-0) [2](#0-1) 

For multi-org configurations, `Shipit.github(organization:)` looks up the org-specific secret via `github_app_config(organization)`: [3](#0-2) 

However, every webhook `Handler` resolves the target `Repository`/`Stack` using a *different* field of the same attacker-controlled JSON body, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits that string and does a DB lookup with no cross-check against the organization that authenticated the request: [5](#0-4) 

`PushHandler` then acts on whatever stacks match that repository, regardless of who actually signed the payload: [6](#0-5) 

Because `repository.owner.login` (used for signature selection) and `repository.full_name` (used for repository resolution) are independent, unrelated fields inside the same request body, an admin of `OrgTwo` — who legitimately possesses `OrgTwo`'s own `webhook_secret` because they configured their own GitHub App, exactly as documented for multi-org setups — can craft a payload with:
- `repository.owner.login` (or top-level `organization.login`) = `"OrgTwo"` → signature verifies successfully with the secret they legitimately hold.
- `repository.full_name` = `"OrgOne/some-private-repo"` → the handler resolves and acts on a stack that belongs to a completely different, unrelated organization hosted on the same Shipit instance.

Before/after the attack:
- Before: `repository_owner("OrgTwo") == authenticating_secret_owner("OrgTwo")`, and it is implicitly assumed that `repository.full_name` also belongs to `OrgTwo`.
- After the crafted request: `repository_owner("OrgTwo") == authenticating_secret_owner("OrgTwo")` still holds, but `repository.full_name` resolves to a stack under `OrgOne`, i.e. `authenticating_org != repository_written_to`.

### Impact Explanation
This lets a tenant with legitimate, narrowly-scoped credentials for their own organization's GitHub App reach and manipulate stacks belonging to a different organization's repositories in the same shared Shipit deployment. Depending on stack configuration (`continuous_deployment`, `merge_queue_enabled`, review-stack provisioning via `pull_request`/`membership`/`check_suite` events, or simply forcing a `GithubSyncJob` with an attacker-chosen `expected_head_sha`), this can result in an unauthorized deploy/sync/rollback trigger against a repository the attacker does not own or control — a cross-tenant, cross-repository write that matches the Critical-impact bar ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires that the Shipit instance be configured for multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md`'s "Using Multiple Github Applications" section and `test/dummy/config/secrets_double_github_app.yml`), and that the attacker has legitimate ownership/administration of at least one of the configured organizations (their own webhook secret), while targeting a stack that belongs to another configured organization. This is a realistic scenario for any SaaS-style or shared Shipit deployment serving multiple orgs/tenants.

### Recommendation
After verifying the HMAC signature against the organization derived from the payload, re-validate that `repository.full_name`'s owner segment matches the same `repository_owner` (or the `organization.login`) used to select the signing secret, and reject the webhook (422) if they diverge. Alternatively, scope handler repository resolution to the authenticated organization rather than trusting `repository.full_name` in isolation.

### Proof of Concept
Assume `config/secrets.yml` (production) is configured as in `docs/setup.md`'s multi-org example, with organizations `OrgOne` (which owns `OrgOne/prod-app`, tracked as a stack in this Shipit instance) and `OrgTwo` (attacker's own org, with known `webhook_secret_two`).

1. Attacker computes `sha1=HMAC(webhook_secret_two, body)` for a crafted `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-existing-in-OrgOne/prod-app>",
  "repository": {
    "full_name": "OrgOne/prod-app",
    "owner": { "login": "OrgTwo" }
  }
}
```
2. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
3. `verify_signature` computes `repository_owner` = `"OrgTwo"` (from `repository.owner.login`), fetches `Shipit.github(organization: "OrgTwo")`, and successfully verifies the signature using the attacker's own legitimate secret.
4. `Shipit::Webhooks::Handlers::PushHandler` is invoked with the same payload; `repository_name` resolves via `payload.dig('repository', 'full_name')` = `"OrgOne/prod-app"`, finds the real `Repository`/`Stack` for `OrgOne`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, causing sync/deploy-adjacent behavior on `OrgOne`'s stack despite the request never being signed by `OrgOne`'s GitHub App.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-26)
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
```
