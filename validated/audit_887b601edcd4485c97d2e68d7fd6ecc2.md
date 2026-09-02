### Title
Cross-organization commit-status forgery bypasses CI gating and enables unauthorized deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit supports multiple GitHub Apps/organizations configured in the same instance (`docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`), each with its own `webhook_secret`. The webhook signature check picks *which* organization's secret to verify against using a payload field the attacker also controls, but the `status` event handler that actually mutates data never re-checks that the target `Commit` belongs to that organization/repository at all. This breaks the binding "organization that authenticated == repository/commit that gets written," letting an attacker who legitimately owns one configured GitHub organization forge a commit status for a commit belonging to a completely different stack/organization hosted on the same Shipit instance, which can satisfy `ci.require`/`ci.blocking` checks and unlock deploys for that other stack.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to validate the request against using `repository_owner`, which is read straight from the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

This only proves that the payload was signed by *some* configured organization's app secret — it does not constrain what the payload's actual content is allowed to reference. Most handlers (`PushHandler`, all `PullRequest::*Handler`s) correctly scope their side effects to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, i.e. the same repository field: [3](#0-2) 

However, `StatusHandler#process` (registered for the `status` event) ignores repository scoping entirely and updates *any* `Commit` row in the database whose SHA matches the attacker-controlled `sha` field, with no relation back to the organization that produced a valid signature or to a `repository` field at all: [4](#0-3) 

So the equality that should hold — `verified organization (used to select webhook_secret) == organization/repository of the commit being mutated` — is not enforced. An attacker who controls Organization B (a legitimate, distinct GitHub org configured in the same Shipit deployment, e.g. `OrgTwo` in `test/dummy/config/secrets_double_github_app.yml`) can send a validly-signed `status` webhook (signed with `OrgTwo`'s real `webhook_secret`, which GitHub will happily deliver for events on OrgTwo's own repos) containing an arbitrary `sha` and `state: "success"`. `Commit.where(sha: params.sha)` will match and update the commit status for that SHA in *any* stack in the Shipit instance, including one belonging to Organization A, regardless of which org's key signed the request.

### Impact Explanation
Commit statuses set via this path feed directly into deploy gating (`ci.require`, `ci.blocking`, `ci.allow_failures` as documented in `README.md`), and into the general CI/deployable-status UI. By forging a "success" status for a required CI context on a commit belonging to a stack outside the attacker's organization, the attacker can help satisfy the conditions Shipit uses to consider a commit deployable, contributing to an **unauthorized deploy** on a stack/repository the attacker does not control — one of the explicitly listed Critical impacts ("an unauthorized deploy, rollback or merge"). It is also a cross-tenant authorization boundary break: `Shipit.github(organization: repository_owner)` is meant to isolate organizations from each other, but `StatusHandler` has no equivalent isolation.

### Likelihood Explanation
Exploitation requires the attacker to control (or have push/webhook-triggering access to) at least one organization/repository that is legitimately configured in the target multi-tenant Shipit instance — this is the documented, supported "Using Multiple Github Applications" configuration, not a hypothetical setup. The attacker needs to know a target commit SHA in the victim stack, which is often public (public GitHub repos, or simply observable via Shipit's own UI/API for that stack, e.g. commit lists). No repository write access, ApiClient token, or webhook secret theft is required — only a legitimately-issued signature from the attacker's own, unrelated organization.

### Recommendation
`StatusHandler` (and any other handler relying purely on payload identifiers that aren't tied to a resolved `Repository`) must scope its lookups through the repository/organization that was actually verified, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack: { repository: repository }).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
where `repository` is resolved the same way other handlers do (`Repository.from_github_repo_name(payload.dig('repository','full_name'))`), and additionally cross-checked against `repository_owner`/the organization used in `verify_signature` so the two can never diverge. More generally, `WebhooksController#verify_signature` should pass the resolved organization down to handlers (or handlers should independently re-derive and enforce it) rather than trusting per-handler payload fields uncorrelated with the field used for signature selection.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `OrgA` and `OrgB`, each with its own `webhook_secret` (supported config per `docs/setup.md`).
2. Attacker controls `OrgB` and knows the SHA (`abc123...`) of a commit in a stack belonging to `OrgA` that is pending a required CI context, e.g. `ci/circleci`.
3. Attacker sends a `status` event webhook to Shipit, signed with `OrgB`'s real `webhook_secret`, with body:
```json
{
  "sha": "abc123...",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgB/attacker-repo" }
}
```
4. `verify_signature` resolves `Shipit.github(organization: "OrgB")` and verifies successfully because it was genuinely signed by `OrgB`.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, finds the commit under `OrgA`'s stack, and marks the `ci/circleci` context as `success`, satisfying `ci.require` for that commit despite the attacker having no access to `OrgA`.

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
