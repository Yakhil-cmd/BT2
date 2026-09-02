### Title
Cross-organization webhook forgery via mismatched signature-selection field and action field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-organization Shipit deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). However, the handler that actually acts on the payload (e.g. `PushHandler`) resolves the target repository from a *different* field of the same payload: `payload.dig('repository', 'full_name')`. Because the signature only proves the payload was signed by *some* organization's registered secret, not that the acted-upon `repository.full_name` belongs to that same organization, an attacker who legitimately controls a webhook secret for one organization (org A) can forge a payload whose `repository.owner.login`/`organization.login` is `org A` (so the correct, known secret is used and the signature check passes) while `repository.full_name` points at a different organization's repository (`org B/private-repo`), causing Shipit to sync/act on `org B`'s stacks.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
```
`Shipit.github(organization:)` looks up a `GitHubApp` instance per-organization, each holding its own independent `webhook_secret` (see the multi-org config example in `config/secrets.development.example.yml`).

- The handlers that then process the very same raw payload (e.g. `app/models/shipit/webhooks/handlers/handler.rb`'s `repository_name` / `app/models/shipit/webhooks/handlers/push_handler.rb`) use:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
```
and resolve the acted-upon `Repository`/`Stack` via `Repository.from_github_repo_name(repository_name)`.

The equality the system implicitly assumes but never enforces is:
`organization authenticated (repository.owner.login used to pick the webhook_secret) == organization of the repository actually written (repository.full_name used by the handler)`.

Because signature verification only proves "this body was HMAC-signed with org A's secret," and the secret's owner (org A) is determined from one payload field while the handler trusts an entirely separate field for which repository/stack to mutate, an attacker who knows org A's webhook secret (e.g., because they administer a webhook on any repository belonging to org A — a capability far short of "repository write access" to org B) can set `repository.owner.login`/`organization.login` to `org A` and `repository.full_name` to `org B/target-repo`, forging a fully "verified" webhook that drives Shipit to run `sync_github` (or other handler actions) against `org B`'s stack.

### Impact Explanation
This breaks the binding "organization authenticated vs. repository written," resulting in cross-organization writes into Shipit's own data model: `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` against a stack belonging to an organization the attacker never authenticated for, and other handlers (`status`, `check_suite`, `membership`, `pull_request`) similarly key off unrelated payload fields (`sha`, team/member logins, PR numbers) without any repository/org linkage check to the verified `repository_owner`. This can pollute commit/build status state, spoof commit statuses that gate deploys, or invent team memberships, which is a legitimate cross-repository-writes impact class in the rules.

### Likelihood Explanation
Exploitability is limited to installations that configure Shipit with multiple GitHub organizations sharing one Shipit instance (the documented multi-org `github:` config), and requires the attacker to control (know) the webhook secret of at least one of those organizations — typically achievable by anyone able to configure webhooks on a repository within that organization, which is a much lower bar than write access to the victim organization's repositories. In single-organization deployments (the common case) `repository_owner` always resolves to the only configured org, so the bug is latent but not exploitable there.

### Recommendation
After signature verification succeeds, enforce that the organization implied by the field(s) actually consumed by handlers (`repository.full_name`'s owner, or `organization.login`) matches the `repository_owner` used to select the webhook secret, rejecting (422) any mismatch before dispatching to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema), and a stack for `org-b/private-repo` tracking a private branch.
2. As a user with permission to create/configure a webhook on any repository under `org-a` (not `org-b`), obtain `org-a`'s `webhook_secret`.
3. Craft a `push` event JSON body where `repository.owner.login` (and/or `organization.login`) is `"org-a"` but `repository.full_name` is `"org-b/private-repo"`, `ref` is the tracked branch, and `after` is an attacker-chosen SHA.
4. Compute `X-Hub-Signature` as `sha1=` + HMAC-SHA1(org-a's webhook_secret, raw body).
5. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "org-a")`, verifies successfully against the known org-a secret, and `PushHandler` then calls `Repository.from_github_repo_name("org-b/private-repo").stacks...sync_github(expected_head_sha: "<attacker sha>")`, driving state changes on `org-b`'s stack without ever authenticating to `org-b`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.example.yml (L18-37)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
```
