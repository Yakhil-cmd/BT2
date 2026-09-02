## Title
Webhook signature is verified against the GitHub App keyed by an attacker-controlled `repository.owner.login`/`organization.login` field, while the event is applied to whatever `repository.full_name` the same unverified payload contains, breaking the binding "organization that authenticated == repository that is written" - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which multi-tenant `GitHubApp` (and thus which `webhook_secret`) to check the `X-Hub-Signature` against by reading `repository_owner` straight out of the **unverified** JSON body, then verifies the HMAC using that organization's secret. All downstream event handlers, however, resolve the repository/stack to actually act on from a *different, independently attacker-controlled* field of the same payload, `repository.full_name`. Because nothing ties "the organization whose secret validated the signature" to "the repository the handler mutates," an actor who can produce a validly-signed webhook for one onboarded organization can forge events (push, status, check_suite, pull_request, membership) that are applied to any other organization's repositories/stacks tracked by the same Shipit instance.

### Finding Description
`verify_signature` is: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`repository_owner` is taken from the raw, unauthenticated request body before any signature check occurs, and is used to pick the per-organization `GitHubApp` (and its `webhook_secret`) via `Shipit.github(organization:)`, which looks up `secrets.github[organization]` in a multi-tenant configuration: [3](#0-2) 

Once the signature check passes (using organization X's secret), the actual event handling code resolves the target repository/stack from a **separate** field of the same payload, `repository.full_name`, with no cross-check against `repository_owner`/organization X: [4](#0-3) [5](#0-4) 

So the verified binding is "organization X's secret validated this request," but the enforced binding needed for safety is "organization X's secret validated this request **for organization X's own repositories**." These are never checked to be equal. A payload can legitimately claim `repository.owner.login` = X (to select X's secret/app) while `repository.full_name` = "Y/some-repo" (an entirely different onboarded organization's repo), and `PushHandler#process` will happily call `stack.sync_github(expected_head_sha: params.after)` on Y's stack using a signature that only ever proved knowledge of X's `webhook_secret`.

### Impact Explanation
In a Shipit deployment configured for multiple GitHub organizations (the documented multi-tenant `secrets.github` schema keyed by organization, `Shipit.github_organizations`), an attacker who can produce a validly signed webhook for *any one* onboarded organization (e.g., they administer that org's GitHub App/webhook settings, or that organization has no `webhook_secret` configured at all — documented as "optional" in `docs/setup.md`, which makes `GitHubApp#verify_webhook_signature` return `true` unconditionally) can forge webhook deliveries that are processed as if they came from a *different* onboarded organization's repository. This lets them:
- Trigger `Stack#sync_github` with an attacker-chosen `expected_head_sha` on another organization's stack via the `push` handler, which can advance the tracked HEAD and, on stacks with `continuous_deployment` enabled, trigger an unauthorized deploy.
- Forge `status`/`check_suite` events to mark arbitrary commits as green/passing on another organization's repository, potentially unblocking merges/deploys gated on CI status.

This is an unauthorized-deploy-class impact crossing an organizational trust boundary that Shipit's multi-tenant webhook config is meant to enforce.

### Likelihood Explanation
Requires a multi-organization Shipit deployment where the attacker legitimately controls (or knows the secret of) one onboarded, lower-trust organization but not the target organization — a realistic scenario for shared Shipit instances serving multiple teams/orgs, and does not require any Shipit session, API token, or privileged Shipit account. Exploitation is a single crafted HTTP POST to `/webhooks` with a correctly computed HMAC using the attacker's own organization's secret.

### Recommendation
After signature verification, re-derive/authorize the organization from `repository.full_name` (or `organization.login` for org-scoped events) and reject the request (or re-verify with the correct organization's `GitHubApp`) if it doesn't match the organization whose secret validated the signature. Do not let `repository_owner` (used to pick the verification key) and `repository.full_name` (used to pick the mutated resource) diverge.

### Proof of Concept
1. Shipit configured with `secrets.github` containing two orgs, `org-a` and `org-b`, each with its own `webhook_secret`; Shipit tracks a stack for `org-b/target-repo`.
2. Attacker (who controls `org-a`'s webhook secret) POSTs to `/webhooks`:
   - Header `X-Github-Event: push`
   - Header `X-Hub-Signature`: HMAC-SHA1 of the raw body computed with `org-a`'s `webhook_secret`
   - Body: `{"repository": {"owner": {"login": "org-a"}, "full_name": "org-b/target-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen-sha>"}`
3. `verify_signature` calls `Shipit.github(organization: "org-a")`, verifies against `org-a`'s secret — passes.
4. `PushHandler` resolves `Repository.from_github_repo_name("org-b/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, acting on `org-b`'s stack despite the request only being authenticated for `org-a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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
