### Title
Cross-organization CI status forgery via webhook signature/repository-scope mismatch, enabling unauthorized continuous deployment - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate a payload against using `repository_owner`, derived from the untrusted request body itself, while `Webhooks::Handlers::StatusHandler` (and the base `Handler#stacks`) act on completely different, independently attacker-controlled fields (`sha` globally, or `repository.full_name` for other handlers) without re-checking that they belong to the organization whose secret validated the request. This breaks the trust binding "organization whose signature authenticated the request" == "repository/commit the handler writes to."

### Finding Description
`WebhooksController#verify_signature` computes the signing organization purely from the JSON body sent by the caller: [1](#0-0) [2](#0-1) 

It then verifies the raw body's HMAC against `Shipit.github(organization: repository_owner).verify_webhook_signature`, i.e. against whichever org's `webhook_secret` matches the `repository.owner.login` (or `organization.login`) field the attacker put in the body. In a multi-organization Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), a caller who legitimately controls one configured organization's webhook secret (e.g. because they administer that org's GitHub App) can correctly sign an arbitrary payload for that org, while filling in unrelated fields that other parts of the pipeline use to select *which* repository/commit is actually written.

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the whole body to handlers, which trust fields inside that same signed-but-attacker-authored body for their own scoping decisions, decoupled from `repository_owner`:

- `StatusHandler#process` does no repository/organization scoping at all — it looks up commits **globally by `sha`**: [3](#0-2) 
- Other handlers (`PushHandler`, `PullRequest::*Handler`) scope via `repository.full_name`, a field entirely independent from `repository.owner.login`: [4](#0-3) 

Because `repository_owner` (used to pick the verifying secret) and `repository.full_name` / `sha` (used to pick the record to mutate) are two unrelated JSON fields under full control of whoever crafts the POST body, nothing enforces that the org whose secret validated the signature is the org that owns the repository/commit actually being written to.

### Impact Explanation
Exploiting this lets an attacker who controls (or knows the webhook secret of) any single organization configured in this Shipit instance forge a "status" webhook that is validated against their own org's secret, yet is applied to a commit belonging to a completely different, unrelated organization's stack tracked by the same instance — because `Commit.where(sha: params.sha)` has no org/repository filter. Injecting a fabricated `success` status for a foreign commit feeds directly into `Commit#add_status`/`Status#schedule_continuous_delivery`, which schedules `ContinuousDeliveryJob` and can trigger `Stack#trigger_continuous_delivery` → `trigger_deploy`, causing an **unauthorized deploy** of that foreign stack: [5](#0-4) [6](#0-5) 

This matches the "unauthorized deploy" Critical-impact criterion: the deploy-gating CI signal is spoofed cross-organization purely because signature verification and write-scoping use different, independently attacker-supplied fields.

### Likelihood Explanation
The `/webhooks` endpoint is unauthenticated by design (any client can POST) and only gated by the HMAC check, so the only prerequisite is possessing a valid `webhook_secret` for *any one* organization configured on the shared Shipit instance — a realistic condition for multi-tenant deployments where each org's own admins configure and know their own webhook secret. No repository write access, GitHub App private key, or session/token is required for the target organization's stack. The `repository`/`sha`/`repository.owner.login` fields are all plain JSON keys with no cross-field integrity check, so crafting the mismatched payload is trivial once one secret is known.

### Recommendation
- After signature verification, re-derive the organization strictly from the same repository object subsequently used by handlers (`repository.full_name`'s owner), and reject the request if it doesn't match `repository_owner` used for verification.
- Have `StatusHandler#process` scope `Commit` lookups by the repository derived from the payload (and validated org), not by `sha` alone.
- Ensure every handler consistently uses one canonical, already-authenticated repository identity rather than trusting separate unrelated body fields for authorization versus data selection.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB` (per `secrets_double_github_app.yml`-style config), each with distinct `webhook_secret`s; `OrgB` has a tracked stack with commit `deadbeef` awaiting a passing CI status to auto-deploy (`continuous_deployment: true`).
2. Attacker, who administers `OrgA` (and thus knows `OrgA`'s `webhook_secret`), builds a `status` event body:
```json
{
  "repository": { "owner": { "login": "OrgA" } },
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/forged"
}
```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s secret and POSTs to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA').verify_webhook_signature(...)`, which succeeds because the signature was legitimately produced with `OrgA`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef')`, finds `OrgB`'s commit (no org check), and creates a `success` `Status` on it.
6. `Status#schedule_continuous_delivery` → `ContinuousDeliveryJob` fires, and if `OrgB`'s stack is otherwise deployable, `Stack#trigger_continuous_delivery` deploys the forged-as-passing commit — an unauthorized deploy on `OrgB`'s stack triggered entirely from `OrgA`'s credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
