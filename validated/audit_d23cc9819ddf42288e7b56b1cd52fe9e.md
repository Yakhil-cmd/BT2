## Title
Cross-organization webhook forgery: signature is verified against `repository.owner.login`/`organization.login`, but events are applied to the repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org config (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, derived straight from the JSON body's `repository.owner.login` (or `organization.login`) field. `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`, used by `PushHandler`, `StatusHandler` and the `PullRequest::*` handlers, instead resolve the target `Repository`/`Stack` from a *different* JSON field: `repository.full_name`. Because the signature check never verifies that these two attacker-supplied fields agree, an actor who legitimately controls the `webhook_secret` for one configured organization can forge a signed payload whose `repository.full_name` points at a completely different, victim organization/repository configured on the same Shipit instance.

### Finding Description
`verify_signature` picks the app config purely from payload content, not from any GitHub-verified identity of the request: [1](#0-0) [2](#0-1) 

The signature itself is then just an HMAC of the raw body, computed with whichever org's secret was picked in step 1: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the *entire* raw payload to handlers, with no re-binding to the organization that was used to authenticate: [4](#0-3) 

Handlers resolve the target repository from a *different* payload field, `repository.full_name`: [5](#0-4) 

`PushHandler` uses that resolution to sync a stack from an attacker-chosen `after` sha, and `StatusHandler` uses it (via `Commit.where(sha:)`, unscoped by repository) to write CI status records that gate deployability: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` does a straightforward `owner/name` lookup with no cross-check against the `organization`/`owner` value that was used for signature verification: [8](#0-7) 

**Trust binding broken (equality that should hold but doesn't):**
`organization used to select/verify the webhook_secret` (`repository.owner.login` or `organization.login`) **≠** `repository whose Stack/Commit state is mutated` (`repository.full_name`). Nothing in `WebhooksController` or `Handler` enforces that `full_name`'s owner segment equals the `owner.login`/`organization.login` that authenticated the request.

### Impact Explanation
On a Shipit instance configured for multiple GitHub organizations (the engine explicitly supports this — see the multi-org secrets template), a party that legitimately possesses the `webhook_secret` for organization *A* (e.g., because they administer their own org's GitHub App/webhook settings) can craft and sign a payload whose `repository.full_name` names a repository belonging to organization *B*. This is accepted by `verify_signature` (which only checked org *A*'s secret) and then processed against org *B*'s `Stack`/`Commit` records:
- Via `StatusHandler`, forge a `success` commit status on a victim commit (`Commit.where(sha:)` is not scoped to the repository at all), which can make an otherwise non-deployable commit appear deployable and, combined with continuous deployment, contribute to triggering an unauthorized deploy on the victim stack.
- Via `PushHandler`, force a resync (`stack.sync_github`) of a victim stack at attacker-chosen times.

This matches the "unauthorized deploy" / cross-repository-writes class of impact called out in scope, since state belonging to a repository/organization the caller never authenticated for is mutated.

### Likelihood Explanation
Requires the attacker to already hold a valid `webhook_secret` for at least one organization configured on the shared Shipit instance — plausible for any multi-tenant/multi-org deployment where org admins configure their own secret (a standard, documented Shipit configuration, not a privileged internal credential). No GitHub App private key, `ApiClient` token, or Shipit session is needed; only an org-scoped webhook secret the attacker is entitled to use for their own org. The forgery itself is a single crafted HTTP POST with a mismatched `owner.login`/`full_name` pair.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), assert that the organization used to select/verify the webhook secret is the same organization embedded in every repository-bearing field the handlers will act on (i.e., derive `repository_owner` and `repository.full_name`'s owner segment from the same trusted source, and reject the request if they diverge). Alternatively, resolve the target `Repository`/`Stack` using the already-verified `repository_owner`, not a second, unchecked payload field.

### Proof of Concept
1. Shipit is configured with two orgs in `Shipit.github` config: `org-attacker` (attacker knows/controls its `webhook_secret`) and `org-victim` (has a `Stack` with continuous deployment enabled).
2. Attacker builds a JSON body for a `status` event:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/victim-repo" }
}
```
3. Attacker signs the raw body with `org-attacker`'s `webhook_secret` and sends `POST /github/webhooks` with `X-Github-Event: status` and the resulting `X-Hub-Signature`.
4. `WebhooksController#verify_signature` computes `repository_owner` from `repository.owner.login` = `"org-attacker"`, calls `Shipit.github(organization: "org-attacker")`, and the signature validates because it was signed with that org's own secret — see [1](#0-0) .
5. `StatusHandler#process` runs unscoped by organization and writes a `success` status onto the victim's commit — see [9](#0-8) , affecting `org-victim`'s deploy-safety state despite the request only ever having authenticated as `org-attacker`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
