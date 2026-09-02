### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON payload. Every downstream `Webhooks::Handlers::Handler` subclass, however, determines *which repository/stack to mutate* using a completely different, equally attacker-controlled field: `repository.full_name`. Because these two fields are never cross-checked, an attacker who legitimately controls a GitHub App installation for one organization configured in Shipit can forge a signature that "passes" for their own org while pointing the payload's `repository.full_name` at a stack belonging to a different organization, causing Shipit to act on a repository the attacker does not own.

### Finding Description
`verify_signature` picks the GitHub App/secret to verify against based on `repository_owner`: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves a distinct `webhook_secret` per organization when Shipit is configured for multiple GitHub organizations: [3](#0-2) 

Once the signature is accepted, the raw JSON payload is dispatched unchanged to handlers: [4](#0-3) 

Every handler, however, resolves the target repository/stack from a *different* payload field, `repository.full_name`, with no comparison back to the organization used for signature verification: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization used to select/verify the webhook_secret (repository.owner.login / organization.login)` == `organization implied by the repository actually mutated (repository.full_name)`.

Before the attack: for a legitimate GitHub webhook, both fields are populated consistently by GitHub itself, so they always match.

After the attacker's crafted request: the attacker (who has a real, valid GitHub App installation/webhook secret for their own organization, `attacker-org`, one of possibly several organizations configured under `secrets.github` per `github_app_config`) computes a correct HMAC using their own secret over a payload where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` fetches and validates against `attacker-org`'s secret and succeeds)
- `repository.full_name` = `"victim-org/victim-repo"` (so `Repository.from_github_repo_name`/`stacks` resolves to a repository/stack Shipit hosts for a completely different organization)

The two sides of the equality diverge, yet no code enforces they must match.

### Impact Explanation
Because handlers key off `repository.full_name` alone, an attacker who is a legitimate GitHub App user for their *own* configured organization can forge push/pull_request/membership-style events for *any other organization/repository Shipit tracks*, without ever having write access to, or a webhook secret for, the victim repository. Concretely, `PushHandler#process` will enqueue `sync_github` for stacks matching the spoofed `full_name`, and PR-event handlers (`ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, etc.) will archive/unarchive review stacks and mutate captured PR label state for the victim's stacks. This is a cross-organization/cross-repository write achieved purely by exploiting the mismatch between the field used for authentication and the field used for authorization of the action, meeting the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
This requires the attacker to have a valid, distinct organization configured in the same Shipit deployment (a realistic multi-tenant setup, supported explicitly by `github_organizations`/`github_app_config`), and no other privileged credential. Any organization admin who can register a GitHub App/webhook for their own org (a routine, low-privilege setup step, not an admin of Shipit itself) can carry out the attack by hand-crafting a single HTTP request with a correctly-computed HMAC over an arbitrary JSON body.

### Recommendation
In `WebhooksController#verify_signature`, after computing `repository_owner`, verify that any repository/organization identifiers used later by handlers (`repository.full_name`, `organization.login`) are consistent with `repository_owner` before dispatching, or better, have handlers resolve the repository strictly from the same organization key that was used to authenticate the signature rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Assume Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `github_app_config`), and `victim-org/victim-repo` has an active stack tracked by Shipit.
2. Attacker, an admin of `attacker-org`'s GitHub App/webhook, knows `attacker-org`'s `webhook_secret`.
3. Attacker builds a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s secret, and the HMAC matches, so the request passes.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` for `victim-org`'s stack — a write action on a repository the attacker never had signing authority over.

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
