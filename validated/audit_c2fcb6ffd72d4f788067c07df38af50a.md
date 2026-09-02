### Title
Cross-tenant webhook forgery via mismatched authentication field (`repository.owner.login`) vs. resolution field (`repository.full_name`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the closest reachable analog to the "actor identified for a check differs from the entity actually acted upon" bug class described in the report. `WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to HMAC-verify a webhook against using `params.dig('repository','owner','login')` (or `organization.login`), while every `Webhooks::Handlers::Handler` subclass (used to actually locate and mutate a `Repository`/`Stack`) resolves the target repository using the **different** field `payload.dig('repository','full_name')`. Nothing ties these two fields together after signature verification succeeds.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to check the signature against based on `repository_owner`: [1](#0-0) [2](#0-1) 

Once `verify_signature` succeeds, the raw payload is dispatched unmodified to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .

Every handler (base class used by `PushHandler`, and independently duplicated in the `pull_request/*` handlers) resolves the `Repository`/`Stack` to act on via `payload.dig('repository', 'full_name')`, not via `repository.owner.login`: [4](#0-3) [5](#0-4) 

In Shipit's multi-organization configuration mode, each GitHub organization has its own `webhook_secret` (`config/secrets.development.example.yml` shows the `github: { org: { webhook_secret: ... } }` shape) [6](#0-5) . Signature verification is an HMAC over the *entire* raw request body computed with the secret for whichever organization `repository.owner.login` names [7](#0-6) .

An attacker who legitimately controls (or has been given) the webhook secret for Organization A — because they themselves configured the GitHub App/webhook that delivers Org A's events into this shared Shipit instance — can construct an arbitrary JSON body where:
- `repository.owner.login = "orgA"` (satisfies `verify_signature`, since they can compute a valid HMAC with Org A's own secret), while
- `repository.full_name = "orgB/private-repo"` (a repository belonging to a completely different, unrelated tenant of the same Shipit instance).

Because the handlers key exclusively off `full_name` and never re-check that its owner matches the verified `repository_owner`, the forged payload is processed as a legitimate event for Org B's stack even though Org A's credentials were used to authenticate it.

Before the attacker's request: Org A's webhook secret authorizes only writes to Stacks belonging to repositories owned by Org A (the intended trust binding is `verified_organization == written_repository.owner`).
After the attacker's request: Org A's webhook secret is used to trigger state changes (`sync_github`, pull-request archive/unarchive, label capture, etc.) on a Stack belonging to Org B — the binding `verified_organization == written_repository.owner` is broken.

### Impact Explanation
This crosses the explicit "organization that authenticated versus the repository that is written" boundary called out as in-scope. Concretely, with `PushHandler`, the attacker can force `stack.sync_github(expected_head_sha: <sha>)` [8](#0-7)  on a stack that belongs to a repository they do not administer, and (via the `pull_request/*` handlers) archive/unarchive review stacks or capture labels on PRs of a repository outside their control [9](#0-8) . For stacks with `continuous_deployment` enabled, forcing a resync of a specific SHA can trigger the deploy pipeline for a commit at a time of the attacker's choosing, i.e. cross-repository writes/unauthorized deploy triggering against a repository the attacker's organization does not own. This satisfies the "High" bar (cross-repository writes / unauthorized deploy trigger).

### Likelihood Explanation
Requires the attacker to hold a legitimate webhook secret for at least one organization already onboarded to the shared Shipit instance (i.e., be a tenant, not an anonymous internet attacker) and to know/guess that another org's repository is also hosted on the same instance (repository names are often public/guessable). This is a realistic scenario for any Shipit deployment serving multiple orgs/tenants with per-org GitHub Apps, which the engine explicitly supports (`config/secrets.development.example.yml` documents multiple-org configuration). Likelihood is Medium: it needs a semi-privileged but out-of-scope-repo tenant, not a fully anonymous actor, but no repository write access, GitHub App private key, or Shipit session/API token is needed to exploit it.

### Recommendation
In `WebhooksController#verify_signature` and/or in `Shipit::Webhooks::Handlers::Handler`, cross-check that the organization used to select/verify the webhook secret (`repository.owner.login` / `organization.login`) matches the owner encoded in `repository.full_name` before dispatching to handlers, e.g. reject the payload if `repository_owner.downcase != full_name.split('/').first.downcase`. Alternatively, resolve the target `Repository` strictly by `(owner, name)` pair taken from the same verified `repository.owner.login`/`repository.name` fields rather than trusting the independent `full_name` string.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `orgA` and `orgB`, each with their own `webhook_secret` (`SA`, `SB`), both tracking Stacks in the same Shipit instance.
2. As an operator with legitimate access to `orgA`'s webhook secret `SA` (e.g., the person who registered `orgA`'s GitHub App/webhook), craft a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<real sha in orgB/victim-repo>",
  "repository": { "full_name": "orgB/victim-repo", "owner": { "login": "orgA" } }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(SA, body)` and POST to `/webhooks`.
4. `WebhooksController#repository_owner` returns `"orgA"`; `verify_signature` succeeds using `SA` [1](#0-0) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` [10](#0-9)  and calls `stack.sync_github(expected_head_sha: ...)` on Org B's stack, even though only Org A's secret was ever validated.

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

**File:** config/secrets.development.example.yml (L18-38)
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
#       teams: # Optional
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```
