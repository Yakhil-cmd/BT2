### Title
Webhook organization used for signature verification is decoupled from the repository the payload writes to, enabling cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, each GitHub organization can be configured with its own `webhook_secret`. `WebhooksController#verify_signature` picks which secret to verify the HMAC against based on `repository.owner.login` taken from the untrusted request body itself, while the actual event handlers (e.g. `PushHandler`) resolve the `Stack`/`Repository` to act on using a *different* field of the same body, `repository.full_name`. Because these two fields are independently attacker-controlled inside one signed blob, a party who legitimately possesses the webhook secret for their *own* organization in the multi-tenant install can forge a payload whose `owner.login` matches their own org (so it passes signature verification with a secret they legitimately hold) while `full_name` points at a different organization's repository, causing Shipit to process the event against that other repository/stack.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config/secret when the install uses the multi-org secrets schema: [3](#0-2) 

Meanwhile, the base `Handler` class (used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves which `Stack`s to operate on using an entirely different payload key, `repository.full_name`, with no re-validation against `repository.owner.login`: [4](#0-3) [5](#0-4) 

The equality that should hold is: `organization whose secret authenticated the request == organization that owns the repository being acted upon`. Because both values are read from the same unauthenticated JSON body, and the signature only proves "this body was HMAC-signed with the secret belonging to the `owner.login` claimed inside it," an attacker who controls (or knows) the webhook secret for *any one* configured organization in the install can set `repository.owner.login` to that organization (making `verify_signature` pass) while setting `repository.full_name` to `victim-org/victim-repo`. The dispatched handler then acts on the victim repository's stack, breaking the binding between "organization that authenticated" and "repository that is written."

### Impact Explanation
This crosses a real trust boundary the engine assumes is enforced by the webhook signature: that only GitHub (holding the org's specific secret) can trigger writes for that org's repositories. With the binding broken, a party who is a legitimate webhook-secret holder for one org in a multi-org Shipit instance can:
- Force `GithubSyncJob` runs and stack state changes (`mark_as_inaccessible!`/`mark_as_accessible!`, commit ingestion) against a repository/stack belonging to a different organization they have no access to, via `PushHandler` → `stack.sync_github`.
- Depending on which handlers are enabled (`status`, `check_suite`, `pull_request`, `membership`), inject fabricated commit statuses, check-run refreshes, or membership/team changes tied to another organization's resources, since those handlers likewise resolve state purely from body fields distinct from `owner.login`.

This matches the "cross-repository writes" / "unauthorized deploy" class of impact called out in scope, because commit-status/check-suite forgery can influence deploy-gating logic for a stack the attacker does not own.

### Likelihood Explanation
This only manifests in installs using the multi-organization secrets schema (`Shipit.github_organizations` returning more than one org), where distinct orgs have distinct `webhook_secret`s but are served by the same Shipit instance. The attacker needs to be a legitimate secret-holder/administrator for at least one of the configured organizations — a realistic scenario for shared/multi-tenant Shipit deployments where different teams manage different orgs' GitHub Apps under one Shipit host. I was not able to fully verify every downstream handler's exploitable impact (e.g., whether `StatusHandler` writes statuses without further GitHub API confirmation) within the available context; this should be confirmed by a background agent with full repo access before remediation.

### Recommendation
Do not select the verification secret from attacker-controlled body content that differs from the field used for authorization decisions later in the pipeline. Concretely:
- Verify the signature using the secret associated with the repository/stack actually resolved by the handler (`repository.full_name`), not a separate `owner.login` field, or
- After verifying with the org derived from `owner.login`, additionally assert that `repository.full_name`'s owner matches that same organization before dispatching to handlers, rejecting the webhook otherwise.

### Proof of Concept
1. Attacker administers the GitHub App for `org-attacker` in a multi-org Shipit deployment and thus knows `webhook_secret` for `org-attacker`.
2. Attacker crafts a `push` webhook JSON body:
   - `"repository": {"owner": {"login": "org-attacker"}, "full_name": "org-victim/victim-repo"}`
   - `"ref": "refs/heads/main"`, `"after": "<attacker-chosen sha>"`
3. Attacker signs the raw body with `org-attacker`'s known `webhook_secret` and sets `X-Hub-Signature` accordingly, `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-attacker")`, which succeeds because the attacker's own secret matches.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("org-victim/victim-repo")` — the victim's stack — and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")`, triggering processing against a repository the attacker does not own or administer.

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
