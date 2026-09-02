Based on my investigation, I found a concrete analog that matches the report's bug class: a value used to authenticate a payload (the organization used to select the HMAC secret) is not the same field the engine actually acts on to determine which repository/stack gets written to.

### Title
Webhook signature is verified against `repository.owner.login`, but stack lookup uses the unverified `repository.full_name` field, allowing cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit installations, `WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate a payload against by reading `repository.owner.login` from the JSON body itself, then all default webhook handlers look up the target `Stack`/`Repository` using a *different* field from that same JSON body: `repository.full_name`. Because HMAC verification is scoped to whichever organization's secret matches `repository.owner.login`, and that field is never cross-checked against `repository.full_name`, an attacker who legitimately controls one configured GitHub organization's webhook secret can craft a payload where `owner.login` names their own org (so the correct secret is selected and the signature verifies) while `full_name` names a repository belonging to a *different* configured organization.

### Finding Description
`WebhooksController#verify_signature` selects the app config with: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves to a per-organization `GitHubApp` instance with its own `webhook_secret`, as configured for multi-org installs: [3](#0-2) [4](#0-3) 

Once the signature is verified using the secret tied to `repository.owner.login`, the raw JSON is dispatched to handlers unmodified: [5](#0-4) 

Every default handler, however, resolves the *target* repository/stack using a **different** field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) [8](#0-7) 

There is no assertion anywhere in `Handler`, `PushHandler`, or the `PullRequest::*Handler` classes that `repository.full_name`'s owner segment equals `repository_owner` (the field the signature was actually verified against). This is the exact class of bug in the report: the field the verification logic reads (`repository.owner.login`) is not the field the business logic acts on (`repository.full_name`) — a binding break between "organization that authenticated" and "repository that is written."

### Impact Explanation
In a multi-org Shipit deployment (explicitly supported and documented in `docs/setup.md`, "Using Multiple Github Applications"), each org has an independently issued webhook secret. An attacker who is a legitimate admin/owner of their own configured GitHub organization (Org A) can obtain Org A's `webhook_secret` indirectly by triggering real webhook deliveries and computing valid signatures for arbitrary bodies they control (since GitHub signs whatever body the App sends, and the App owner controls what events fire and can also just compute the HMAC themselves if they have the app's webhook secret from their own GitHub App settings — they are the org admin who configured it). They can then send a forged POST to `/webhooks` with:
- `repository.owner.login` = `"orgA"` (so `Shipit.github(organization: "orgA")` is selected and the signature verifies successfully with Org A's secret)
- `repository.full_name` = `"orgB/private-repo"` (a stack belonging to a different, unrelated organization also hosted on the same Shipit instance)

Because handlers key exclusively off `full_name`, this lets Org A's admin trigger `GithubSyncJob`, pull-request open/close/archive/unarchive actions, or CI status/commit-status writes against Org B's stacks — data and state belonging to a repository the attacker has no legitimate access to. This is a cross-repository write across an organizational trust boundary, satisfying the Critical-severity bar ("cross-repository writes").

### Likelihood Explanation
This requires the Shipit instance to be configured with multiple GitHub organizations (a documented, supported configuration) and requires the attacker to control (be an admin of) one of those configured orgs — a low bar for an "unprivileged attacker" relative to the other orgs on the same Shipit instance, since Shipit trusts every configured org's GitHub App equally. No `ApiClient` token, no `User` session, and no direct repository write access to the victim org are required — only webhook-secret-level trust for their own org.

### Recommendation
After signature verification succeeds, revalidate that `repository.owner.login` (or `organization.login`) in the payload matches the owner segment of `repository.full_name` before dispatching to handlers, or better: derive the target repository strictly from the same field used for signature/organization selection, rejecting payloads where they diverge.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-org setup), and create a `Stack` for `orgB/private-repo`.
2. As the admin of `orgA`'s GitHub App, compute a valid `X-Hub-Signature` HMAC over a crafted JSON push payload using `orgA`'s `webhook_secret`, where:
   - `repository.owner.login` = `"orgA"`
   - `repository.full_name` = `"orgB/private-repo"`
   - `ref` = `"refs/heads/master"`, `after` = attacker-chosen SHA
3. POST this payload with header `X-Github-Event: push` to `/webhooks`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "orgA")` and the HMAC verifies successfully.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/private-repo")`, matching `orgB`'s stack, and enqueues `GithubSyncJob`/state changes for that stack — despite the request never being signed by `orgB`'s webhook secret.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L48-54)
```ruby
          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
