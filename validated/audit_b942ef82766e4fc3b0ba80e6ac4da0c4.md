### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the (unauthenticated) `repository.full_name`, allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to check the HMAC signature based on `repository.owner.login` (or `organization.login`) in the JSON body, but the event handlers that subsequently act on the payload resolve the target `Stack`/`Repository` using an entirely different field, `repository.full_name`. Nothing binds these two values together, so a payload can be legitimately "signed" for organization A while directing the actual write (sync, status update, PR merge-queue action, archive/unarchive, label capture, etc.) at a stack belonging to organization B.

### Finding Description
`verify_signature` picks the app/secret to validate against like this: [1](#0-0) 

and: [2](#0-1) 

So the *authentication* decision is scoped to whatever organization is named in `repository.owner.login` (falling back to `organization.login`). `GitHubApp#verify_webhook_signature` further weakens this: if that organization's `webhook_secret` is blank/unconfigured, verification is skipped entirely and any payload is accepted: [3](#0-2) 

After verification, `create` forwards the *entire raw JSON body* — unfiltered — to every registered handler for the event: [4](#0-3) 

But the base `Handler` class (and every concrete handler: `PushHandler`, `StatusHandler`, `ReopenedHandler`, `LabeledHandler`, `EditedHandler`, `LabelCapturingHandler`, etc.) resolves the repository/stack to act on using a *different* field, `repository.full_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

This is the exact bug-class analog from the report: a value used to grant trust (`repository.owner.login`, which selects the verifying secret) is never bound to the value actually acted upon (`repository.full_name`, which selects the mutated resource) — the equality `organization_authenticated == repository_written` is never enforced. In the LeXscrow report, `amountDeposited` recorded for a rejected depositor was never cleared/reconciled against the balance actually used later; here, the “identity” checked at authentication time is never reconciled against the “identity” used at action time.

### Impact Explanation
In any multi-tenant Shipit deployment (multiple GitHub organizations configured under `Shipit.github`, as shown in `config/secrets.development.shopify.yml`), an attacker who can produce a validly-signed webhook for *any one* onboarded organization (e.g., because that organization's `webhook_secret` is unset/blank, or because they administer that org's own GitHub App/webhook settings) can set `repository.full_name` in the JSON body to a *different* organization's repository. This lets them:
- Trigger `PushHandler` to force `stack.sync_github(expected_head_sha:)` against a foreign repo/stack.
- Post fabricated commit statuses via `StatusHandler`.
- Archive/unarchive review stacks, capture/alter labels, or resolve pull requests via the `PullRequest::*` handlers for a repository they do not own.

This is a cross-repository write triggered without the attacker ever obtaining write access to, or a valid `webhook_secret` for, the targeted organization/repository — matching the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Requires: (a) a Shipit instance configured for more than one GitHub organization (a documented, supported configuration, not a misconfiguration falling outside scope), and (b) the ability to produce a valid signature for at least one of those organizations (either because its `webhook_secret` is blank — `verify_webhook_signature` returns `true` unconditionally in that case — or because the attacker controls that organization's own webhook delivery). No repository write access, `ApiClient` token, or privileged Shipit account is needed; only crafting/forging one HTTP POST to `/webhooks`.

### Recommendation
Bind the verified organization to the repository being mutated: after `verify_signature` succeeds, re-derive the organization from `repository.full_name` (the same field handlers use) and confirm it matches the organization whose secret validated the signature (or, simpler, always compute `repository_owner` from `repository.full_name`'s owner segment instead of the separate `repository.owner.login`/`organization.login` fields). Additionally, do not treat a blank `webhook_secret` as an automatic pass — require every onboarded organization to have a configured secret before accepting webhooks for its repos.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` (webhook_secret unset/blank or otherwise known to attacker) and `org-b` (private, victim-owned, contains a tracked `Stack`).
2. Attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<any/valid-for-org-a>
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "org-a")`; because `org-a`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the signature header [8](#0-7) .
4. `create` passes the full payload to `PushHandler`, which resolves `stacks` via `repository.dig('repository','full_name')` = `"org-b/victim-repo"` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack [9](#0-8) , triggering an unauthorized sync/deploy pipeline action against `org-b`'s repository using only `org-a`'s (weak/absent) credentials.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
