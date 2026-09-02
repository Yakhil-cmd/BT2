### Title
Webhook signature verification authenticates the payload's organization, but downstream handlers act on an unauthenticated `repository.full_name` from the same payload — allowing cross-organization writes in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
In a multi-organization Shipit configuration (see `config/secrets.development.shopify.yml`, which shows `github.somegithuborg` and `github.someothergithuborg` each with their own independent `webhook_secret`), `WebhooksController#verify_signature` selects *which* organization's secret to use for HMAC verification based on a value pulled straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and `Shipit.github(organization: repository_owner)` looks up the corresponding `GitHubApp`/`webhook_secret` via `github_app_config`: [3](#0-2) 

Once `verify_signature` passes, `WebhooksController#create` dispatches the entire raw payload to handlers such as `Shipit::Webhooks::Handlers::PushHandler`, which resolve the target `Repository`/`Stack` using a *different* field of the same payload — `repository.full_name` — with no cross-check that it belongs to the organization that was actually authenticated: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login / organization.login) == organization of the repository whose Stacks are mutated (repository.full_name)`

Nothing in the code enforces this equality — `repository_owner` and `repository.full_name` are two independent, attacker-controlled JSON fields inside the same HTTP body that only needs to be signed with *one* organization's secret. Since HMAC verification only proves knowledge of *a* configured `webhook_secret` for *some* organization (identified by `repository_owner`), and not that the payload actually originated from GitHub for the repository named in `repository.full_name`, an actor who legitimately controls Org A's GitHub App/webhook configuration in a multi-org Shipit instance (and therefore knows Org A's `webhook_secret`, which they can obtain by configuring the App or by capturing one legitimate delivery) can forge a payload where `repository.owner.login = "orgA"` (so the signature check passes) but `repository.full_name = "orgB/some-other-repo"` (so the handler acts on a stack under an entirely different, unrelated organization).

### Impact Explanation
This breaks a repository/organization-trust boundary that the deployment-trust model of the engine relies on: a signature valid for Org A is treated as authorization to act on any repository named anywhere in the same JSON body, including repositories owned by Org B. Concretely with `PushHandler`, this can trigger `stack.sync_github(expected_head_sha:)` for stacks belonging to a repository outside the authenticating organization; other handlers (`membership`, `pull_request`, `status`, `check_suite`) resolve their target the same way (`repository.full_name` / `Repository.from_github_repo_name`), so this pattern extends to team membership manipulation, PR/review-stack state changes, and commit statuses for repositories the forging organization does not own. This matches the "Critical - cross-repository writes" / "unauthorized deploy" impact bucket, since it is effectively a cross-organization/cross-repository write triggered by a signature that only proves possession of a different organization's secret.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (the single-org `github:` config in `config/secrets.development.example.yml` does not enable this, since there is only one `webhook_secret` to authenticate against, matching the actual org used everywhere). In the multi-org layout demonstrated by `config/secrets.development.shopify.yml`, however, any party that legitimately administers one configured GitHub organization/App (and thus its `webhook_secret`) can immediately mount this attack against sibling organizations sharing the same Shipit instance, without needing an `ApiClient` token, a Shipit session, or repository write access on the target org — only knowledge of their own org's webhook secret, which they are entitled to have.

### Recommendation
After `verify_signature` resolves the authenticating organization from `repository_owner`, that same organization identity should be threaded through to the handler layer and cross-checked against the owner segment of `repository.full_name` before any `Repository`/`Stack` lookup is performed (e.g., reject the webhook, or scope `Handler#stacks` lookups, to repositories whose owner matches the authenticated organization).

### Proof of Concept
1. Deploy Shipit with a multi-org GitHub config, e.g. two orgs `orgA` and `orgB`, each with distinct `webhook_secret`s (as in `config/secrets.development.shopify.yml`).
2. As an administrator of `orgA`'s GitHub App, obtain `orgA`'s `webhook_secret` (you are entitled to configure/rotate it).
3. Craft a JSON payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
}
```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#repository_owner` returns `"orgA"`; `Shipit.github(organization: "orgA")` succeeds and `verify_webhook_signature` passes because the signature was computed correctly with `orgA`'s secret.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/target-repo")`, and any not-archived stack on that branch has `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` invoked — a write triggered against `orgB`'s repository/stack using only `orgA`'s webhook credential.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
