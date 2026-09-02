### Title
Cross-organization webhook confusion allows forged CI status / sync events for repositories outside the authenticating organization - ([File: app/controllers/shipit/webhooks_controller.rb](), [File: app/models/shipit/webhooks/handlers/handler.rb]())

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate an incoming payload against using an attacker-controlled field (`repository.owner.login` / `organization.login`) read from the *unverified* request body, before the HMAC signature has actually been checked. Once verification passes, the individual `Handler` subclasses (e.g. `PushHandler`, `StatusHandler`) look up the target `Repository`/`Commit` using a **different** field from the same payload (`repository.full_name`, or a bare `sha` with no owner scoping at all). Because these two lookups are not required to reference the same repository/organization, a party who legitimately controls the webhook secret for *one* organization configured in Shipit can craft a payload that authenticates as their own organization but whose event content targets a completely different, unrelated organization's repository/commit.

### Finding Description
This mirrors the report's bug class: a value that determines *whose credentials/authority is checked* (the webhook-secret owner) diverges from the value that determines *what gets acted upon* (the repository/commit actually mutated), i.e. the binding `authenticated_organization == written_repository` is not enforced.

- `WebhooksController#verify_signature` resolves the signing organization purely from the JSON body: [1](#0-0) [2](#0-1) 

  `repository_owner` falls back to `organization.login` and is used solely to pick which `Shipit.github(organization: …)` app/secret to verify the HMAC against.

- After the signature check passes, the actual event handlers re-read the payload independently to decide what to act on, with no cross-check against the value used for signature selection: [3](#0-2) [4](#0-3) [5](#0-4) 

  `StatusHandler` is especially notable: it resolves the target purely by `Commit.where(sha: params.sha)` with **no repository/organization scoping whatsoever**, and directly writes a CI status record from unauthenticated-relative-to-target-repo data: [6](#0-5) 

Since Shipit supports multiple GitHub organizations each with their own `webhook_secret` (via `Shipit.github(organization:)`), anyone who is an admin of one org onboarded into the same Shipit instance and thus knows/controls that org's `webhook_secret` can pass `verify_signature` while embedding a `repository.full_name` (for push) or a bare commit `sha` (for status) belonging to a different organization/stack. This breaks the deployment-trust binding of "organization that authenticated" vs "repository that is written."

### Impact Explanation
- Via `StatusHandler`, an attacker who legitimately controls only their own organization's webhook secret can inject arbitrary commit-status rows (`commit.create_status_from_github!`) against **any** commit SHA known to them in **any** stack tracked by the Shipit instance, since lookup is unscoped by repository/org. Commit statuses are consumed by `Stack#trigger_deploy`/CI-required checks (`ci.require`) to gate whether a commit is `deployable?`, so forging a passing status can help satisfy CI gating for an unauthorized deploy of another team's stack.
- Via `PushHandler`, the same organization confusion lets an attacker force-enqueue a `GithubSyncJob`/`sync_github` for a stack belonging to a different organization with an attacker-chosen `expected_head_sha`, even though they never authenticated as that organization.
- This satisfies the "unauthorized deploy" / cross-repository-write impact bar, because it lets a party who only controls one org's webhook trust boundary act on a stack outside that boundary.

### Likelihood Explanation
Requires only that the attacker legitimately administers/owns one GitHub organization already onboarded to the shared Shipit instance (and therefore knows/sets its own webhook secret) and knows or can guess a target commit SHA / repository full name in another organization's stack — no `ApiClient` token, `webhook_secret` of the victim org, GitHub App private key, or the victim organization's own credentials are needed. This is realistic in any multi-tenant Shipit deployment serving several GitHub organizations.

### Recommendation
Bind signature-selection and processing to the same authenticated field: after computing `repository_owner` used to select the signing org, re-verify inside each `Handler` (or centrally in `WebhooksController`) that `payload.dig('repository','owner','login')` (or `organization.login`) equals the organization actually owning the `Repository`/`Commit`/`Stack` being modified, rejecting the event otherwise. In particular, `StatusHandler` should scope `Commit` lookups by the repository/organization derived from the verified webhook context, not merely by `sha`.

### Proof of Concept
Conceptual PoC (cannot be executed without a running multi-org Shipit instance):
1. Attacker is an owner of GitHub org `attacker-org`, which is configured in Shipit with `webhook_secret: S`.
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim-repo-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Attacker signs the raw body with `S` and sends `X-Hub-Signature: sha1=<hmac>` and `X-Github-Event: status` to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s webhook config, and the signature validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit in an unrelated organization's stack — and writes a forged "success" status for it, independent of `attacker-org` having any relationship to that stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```
