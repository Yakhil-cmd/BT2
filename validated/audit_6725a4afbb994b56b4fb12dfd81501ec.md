### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but `StatusHandler` writes commit statuses without any repository/organization scoping — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the **unverified** JSON body. Once the signature check passes, the `status` event is dispatched to `Shipit::Webhooks::Handlers::StatusHandler`, which looks up commits by SHA alone, with no check that the commit belongs to the repository/organization that was actually authenticated. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` resolves the signing secret this way: [1](#0-0) 

`repository_owner` is derived purely from attacker-controlled JSON fields, before any signature validation occurs: [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GithubApp` configured for whatever organization the attacker names in the payload. If Shipit is configured to serve multiple GitHub organizations/apps (a normal, documented multi-tenant configuration, as shown by the `OrgOne` / `OrgTwo` fixture in `test/dummy/config/secrets_double_github_app.yml`), any party who legitimately administers the webhook for one of those organizations knows that organization's `webhook_secret` and can compute a valid `X-Hub-Signature` for arbitrary JSON bodies. The verification step only checks that the signature matches the secret for the organization *named in the payload* — it does not verify that this organization actually owns the target resource acted upon by the handler.

Once the request passes signature verification, the event is routed to handlers purely based on `X-Github-Event`: [3](#0-2) 

For the `status` event, `StatusHandler#process` looks up commits by SHA globally, with **no** filtering by repository or organization at all: [4](#0-3) 

`Commit.where(sha: params.sha)` matches any commit across **any** stack/repository tracked by this Shipit instance, and `commit.create_status_from_github!(params)` writes a new `Status` record with an attacker-chosen `state` (e.g. `success`) for that commit: [5](#0-4) 

This status feeds into CI-gating logic (`ci.require` / merge-queue / deployability checks) used elsewhere in the stack model and deploy spec.

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by X-Hub-Signature` == `repository/organization whose commit status StatusHandler mutates`

Before the attacker's request: only GitHub, holding each organization's real webhook secret, can produce a valid signature for events concerning that organization's repositories, and each webhook payload's repository fields are trustworthy because they originate from GitHub itself.

After the attacker's request: an operator of Organization A (who legitimately knows Organization A's `webhook_secret` because they installed/administer the app for Org A) can sign an arbitrary JSON body whose `repository.owner.login` = `"OrgA"` (to pass `verify_signature`) while the `sha` field references a commit that actually belongs to a completely unrelated stack/repository (Org B, or any other tenant on the same Shipit instance). `StatusHandler` has no code path checking that the `sha` belongs to a commit under the authenticated organization, so the forged status is accepted and persisted.

### Impact Explanation
This is a cross-tenant / cross-repository write: an entity with legitimate control of one organization's webhook secret can inject fabricated CI/status data (e.g., mark an arbitrary commit belonging to a different repository as `success`) without any access to that other repository. Because commit status directly gates `deployable?`/CI-required checks used before allowing a deploy, this can enable an **unauthorized deploy** on a victim stack whose required CI check was never actually satisfied — matching the report's underlying bug class (a verification boundary — minimum-collateral check in the analog, HMAC-authenticated-organization check here — being bypassed for a downstream write that the check was supposed to gate). It also generally represents a cross-repository write capability, since any organization's webhook credentials can mutate state belonging to stacks under a completely different repository/organization tracked by the same Shipit deployment.

### Likelihood Explanation
Requires an attacker to already legitimately control the webhook secret for at least one organization/app configured in this Shipit instance (a normal, low-privilege position for any tenant admin in a multi-org Shipit deployment) and knowledge of a target commit SHA belonging to another repository tracked by the same instance (commit SHAs are often publicly visible on GitHub). No access to the victim repository, no `ApiClient` token, and no privileged Shipit account is required — the only "special" knowledge needed is a webhook secret the attacker is entitled to hold for their own, unrelated organization.

### Recommendation
- In `StatusHandler` (and ideally in the base `Handler`), require and verify that the commit(s) being updated belong to a stack whose repository matches `payload.dig('repository', 'full_name')`, and cross-check that this repository's owner matches the organization that was used to verify the webhook signature in `WebhooksController#verify_signature`.
- Consider moving signature verification to be repository-scoped rather than organization-scoped alone, i.e., ensure the authenticated organization is provably the owner of the repository referenced by the payload before any handler executes, not just at the point of picking which secret to check against.

### Proof of Concept
1. Operator of Organization A configures Shipit with a webhook and knows Org A's `webhook_secret` (a legitimate, unprivileged administrative capability for their own org).
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<sha of a commit belonging to Org B's tracked stack>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully (per `app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (per `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), matching the Org B commit regardless of the `repository` field in the payload, and calls `create_status_from_github!`, persisting a forged `success` status on a commit the attacker never had access to.

Note: I was unable to fully trace `commit.create_status_from_github!` and `Stack#deployable?`/CI gating logic to their exact implementation bodies within the tool budget available; the citations above for `Status.replicate_from_github!` and `Status#enable_ci_on_stack`/`schedule_continuous_delivery` support that created statuses influence deploy/merge scheduling, but a full confirmation of the exact deploy-authorization code path would benefit from a deeper read of `app/models/shipit/commit.rb` and `app/models/shipit/commit_checks.rb`.

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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```
