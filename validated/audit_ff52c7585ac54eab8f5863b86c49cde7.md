### Title
Webhook signature is bound to `repository.owner.login`/`organization.login` but handlers act on `repository.full_name`, allowing a valid-webhook-secret holder for one org to write into stacks belonging to any other configured org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments (`Shipit.github(organization:)` config with per-org `webhook_secret`), `WebhooksController#verify_signature` selects the HMAC secret to validate a request using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')`. [1](#0-0) [2](#0-1) 

Every event handler, however, resolves the affected repository/stack using an entirely different field of the same JSON body: `repository.full_name`. [3](#0-2) [4](#0-3) 

`Shipit.github_app_config` selects the app/secret purely by organization name, independent from the repo the payload claims to target: [5](#0-4) 

### Finding Description
The binding the engine is supposed to enforce is: **the organization whose webhook secret authenticated the request == the organization that owns the repository the request is allowed to mutate.** That equality is never checked. The signature check only verifies that the raw body's HMAC matches the secret belonging to `repository.owner.login` (or `organization.login` as a fallback) — a value read directly out of the same untrusted payload it is meant to protect. Once verification passes, the actual write target is picked by a *second, independent* field, `repository.full_name`, which is never cross-checked against `repository.owner.login`.

Concretely:
- `verify_signature` picks the `GitHubApp`/secret for org `X` using `repository.owner.login = X`, and validates the raw POST body against that secret.
- If it validates, `WebhooksController#create` dispatches the *entire, attacker-supplied* JSON body to handlers. [6](#0-5) 
- `Handler#stacks` / `#repository_name` and every push/pull_request/status handler locate the target `Repository`/`Stack` using `repository.full_name`, e.g. `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` where `stacks` is derived from `repository.full_name`. [7](#0-6) [3](#0-2) 

Because `repository.owner.login` (used for authentication) and `repository.full_name` (used for the actual write) are two separate, independently attacker-controlled fields inside the same signed body, an attacker who legitimately possesses/controls the webhook secret for **org A** (e.g., because they administer the Shipit GitHub App installed on their own org, or otherwise legitimately hold that one org's `webhook_secret`) can craft a payload with `repository.owner.login = "orgA"` (so the HMAC validates against orgA's secret) but `repository.full_name = "orgB/some-other-repo"`. The request passes signature verification under org A's secret, then the handler acts on org B's stack — e.g., triggering `GithubSyncJob`, injecting fabricated commit `status` events (`StatusHandler`), fabricating `check_suite` completions to trigger deploy-gating check runs, or creating `PullRequest`/`ReviewStack` records — for a repository/org the attacker has no relationship to at all.

This is the direct analog of the Sherlock report's root cause: a value is verified/trusted for one purpose (the Merkle proof / claim eligibility in the original bug; the webhook secret/org here) while a *different, unchecked* copy of similar data is what's actually acted upon (`getVestedFraction`/claim amount there; `repository.full_name` here).

### Impact Explanation
This breaks the organization-isolation boundary that per-org `webhook_secret` configuration is meant to provide: cross-repository/cross-organization writes into stacks the attacker's org has no authorization over. Depending on the handler exploited this enables:
- Forged `push` events to trigger unauthorized `GithubSyncJob`/`sync_github` for a foreign org's stack.
- Forged `status`/`check_suite` events to fabricate CI state for a foreign org's commits, which can unblock a continuous-deployment stack's deploy gating (`enable_ci_on_stack`, `create_status_from_github!`).
- Forged `pull_request` events to create/mutate `ReviewStack`/`PullRequest` records for a foreign org's repository.

This matches the "cross-repository writes / unauthorized deploy" Critical-tier impact category.

### Likelihood Explanation
Requires the attacker to already legitimately hold a valid `webhook_secret` for at least one org configured in the multi-org `Shipit.github` config (which is a lesser privilege than the org under attack) — a realistic scenario for any Shipit deployment shared across multiple GitHub orgs, since each org's admins are expected to be mutually untrusted with respect to other orgs' stacks. No repository write access, GitHub App private key, or Shipit session/API token is required to reach the victim org.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after the signature is validated for the organization derived from the payload, enforce that every handler's target repository (`repository.full_name`'s owner segment) matches the exact organization whose secret validated the request; reject the request otherwise. Alternatively, derive `repository_owner` strictly from `repository.full_name` (single source of truth) rather than from the separate `repository.owner.login`/`organization.login` fields, and have handlers reuse that same normalized value instead of trusting `full_name` independently.

### Proof of Concept
Given a Shipit instance configured with two GitHub App orgs, `orgA` (attacker-controlled webhook secret) and `orgB` (victim, has a Shipit stack tracking `orgB/victim-repo`):

1. Attacker computes `sha1=HMAC(orgA_webhook_secret, body)` for a forged push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
2. POST to `/github/webhooks` with header `X-Hub-Signature: sha1=<computed>`.
3. `verify_signature` calls `Shipit.github(organization: "orgA")` (from `repository.owner.login`), validates the HMAC against `orgA`'s secret — passes. [1](#0-0) 
4. `create` dispatches the full body to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` and enqueues `sync_github` for that foreign stack, despite the request never having been authenticated by `orgB`'s secret. [3](#0-2) [7](#0-6)

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
