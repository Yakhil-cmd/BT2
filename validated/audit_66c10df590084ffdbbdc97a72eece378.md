### Title
Webhook signature is verified against the `repository.owner.login` field but downstream handlers act on the unrelated, unverified `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the JSON body. Once verification passes, `WebhooksController#create` dispatches the *entire* raw JSON payload to the registered handlers, which resolve the target `Repository`/`Stack` using a **different** field, `repository.full_name`. Because these two fields are never cross-checked, an attacker who controls (and knows the `webhook_secret` for) one organization configured in `Shipit.github` can forge a signature valid for their own org while pointing `repository.full_name` at a victim organization's repository, causing handlers to act on that victim's stacks.

### Finding Description
`verify_signature` picks the app/secret purely from the attacker-controlled JSON body, before any authenticity is established: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is read straight from the unverified body: [2](#0-1) 

This is a legitimate design when Shipit is configured for multiple GitHub organizations (see `config/secrets.development.shopify.yml`, which shows a `github:` map keyed by org, each with its own `webhook_secret`). The HMAC check only proves "whoever crafted this payload knows the secret belonging to the org named by `repository.owner.login` / `organization.login`" — it says nothing about the rest of the payload.

Once `verified` is true, the full raw payload is dispatched unchanged to handlers: [3](#0-2) 

Handlers resolve the affected `Repository`/`Stack` using `repository.full_name`, a completely independent field from the one used for signature selection: [4](#0-3) [5](#0-4) 

For example, `PushHandler` triggers a GitHub sync on whatever stack matches `repository.full_name`: [6](#0-5) 

And `StatusHandler` writes commit statuses (used to gate deploy safety/"deployable" checks) keyed only by commit `sha`, with no repository/org check at all: [7](#0-6) 

The binding that should hold is: **organization that authenticated the signature == organization owning the repository the handlers act on**. This binding is broken: the signature only authenticates `repository.owner.login`, while `PushHandler`, `StatusHandler`, `PullRequest::*Handler`, and `CheckSuiteHandler` all key off `repository.full_name`, a sibling field in the same JSON body that is never compared to `repository.owner.login`.

### Impact Explanation
An attacker who legitimately controls one GitHub organization onboarded to a shared multi-tenant Shipit instance (and therefore knows that org's `webhook_secret`, a supported, documented configuration per `config/secrets.development.shopify.yml` / `config/secrets.development.example.yml`) can forge a webhook payload that:
- Sets `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` picks their own secret and the HMAC passes.
- Sets `repository.full_name` to a victim organization's repository.

This lets the attacker:
- Force a `push` event that triggers `GithubSyncJob`/`sync_github` on a victim's stack (`PushHandler`), and
- Inject arbitrary commit statuses via `StatusHandler` for any commit `sha` (since it only filters `Commit.where(sha:)` with no repository/org scoping) — potentially marking unsafe commits "deployable"/green and enabling an **unauthorized deploy** on a stack the attacker has no access to, and
- Trigger `pull_request`/`check_suite`/`membership` handlers against victim repositories/teams.

This matches the required Critical impact category of "an unauthorized deploy" driven by cross-organization write/trust confusion.

### Likelihood Explanation
Requires the attacker to control one org configured in Shipit's multi-org `github:` config (i.e., know that org's `webhook_secret`) — a scenario the codebase explicitly supports (multi-tenant secrets file) and does not treat as fully trusted for all other orgs. No session, `ApiClient` token, or GitHub App private key for the victim org is needed; only the attacker's own webhook secret and knowledge of a target repository's `full_name`/branch/commit sha, both of which are typically public information.

### Recommendation
After selecting the GitHub App/organization based on `repository_owner` and verifying the signature, re-validate that `repository.full_name` (and `organization.login`, if present) actually belongs to the same organization that was used to select the secret, rejecting the webhook if they diverge. Alternatively, since GitHub always signs webhooks per-installation, verify using the secret associated with the App that delivered the webhook (e.g. via the `installation.id` in the payload matched against configured `installation_id`) rather than trusting an easily-attacker-chosen `owner.login`/`organization.login` field to pick the verification secret.

### Proof of Concept
1. Attacker controls "AttackerOrg", which is configured in Shipit's `github:` map with `webhook_secret: S`.
2. Attacker crafts a `push` JSON payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<victim-sha>",
  "repository": {
    "full_name": "VictimOrg/victim-repo",
    "owner": { "login": "AttackerOrg" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")`, verifies the HMAC with secret `S`, and passes. [8](#0-7) 
5. `create` dispatches the payload to `PushHandler`, which resolves `Repository.from_github_repo_name("VictimOrg/victim-repo")` and calls `sync_github` on all matching, non-archived stacks on that branch — a repository the attacker has no legitimate relationship to. [9](#0-8) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
