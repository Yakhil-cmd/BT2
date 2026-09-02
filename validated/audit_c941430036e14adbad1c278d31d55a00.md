### Title
Cross-organization CI status forgery via webhook signature/repository binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary

### Finding Description
In a multi-tenant Shipit deployment (the "Using Multiple Github Applications" configuration documented in `docs/setup.md`, where `github` config has one sub-config per GitHub organization), `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, taken from the *inbound payload itself*: [1](#0-0) [2](#0-1) 

That is, the org used to *authenticate* the request (`params.dig('repository','owner','login')`) is an attacker-controlled field in the same JSON body being verified. Downstream, event handlers such as `Shipit::Webhooks::Handlers::StatusHandler#process` never re-check that field against anything: it looks up commits purely by SHA, globally, with no repository or organization scoping at all: [3](#0-2) 

`Commit#create_status_from_github!` / `Status.replicate_from_github!` then create a real `Status` row on whatever `Commit` matches that SHA — irrespective of which organization owns the underlying repository — and this immediately triggers merge/deploy scheduling: [4](#0-3) [5](#0-4) 

The broken binding, stated as an equality that should hold but doesn't:
`organization_that_authenticated(repository_owner in payload) == organization_owning(commit whose status gets written)`

Before the attack: only GitHub's own delivery for Org B's repos (signed with Org B's `webhook_secret`) can create statuses for Org B's tracked commits.
After the attack: an attacker who legitimately controls (and knows the `webhook_secret` for) Org A — a *different*, unrelated org also configured on the same Shipit instance — can craft a `status` event payload where `repository.owner.login = "OrgA"` (so `verify_signature` picks Org A's secret and the HMAC matches) while `sha` is any commit SHA belonging to a stack under Org B. `WebhooksController` verifies successfully using Org A's secret, then dispatches to `StatusHandler`, which applies the forged status to Org B's commit without any check that Org A actually owns that commit/repository.

### Impact Explanation
This lets a party who is authorized only for Org A forge a `success`/`pending` CI status for arbitrary tracked commits belonging to Org B. `Status#after_create :schedule_continuous_delivery` and `Commit#add_status` (`stack.schedule_merges if new_status.pending? || new_status.success?`) mean this forged status can bypass real CI gating and trigger the merge queue / deploy-readiness logic for Org B's stacks — an unauthorized-deploy-adjacent condition (CI-gate bypass enabling merge/deploy scheduling) achieved purely by crossing an organization boundary that the signature-verification code was supposed to enforce.

### Likelihood Explanation
Requires: (a) a Shipit instance configured with more than one GitHub organization (documented, supported configuration), and (b) the attacker being a legitimate/authenticated party for at least one of those configured organizations (i.e., they know that org's own `webhook_secret`, which they legitimately possess as that org's admin/integrator — not Org B's secret, not a Shipit `ApiClient` token, and no privileged access to Org B). Since `StatusHandler` does zero repository/org scoping, exploitation is a single crafted, correctly-HMAC'd HTTP POST to `/webhooks` — no other precondition needed.

### Recommendation
- `WebhooksController#verify_signature` must not let the payload itself pick which secret validates the payload's own authenticity for cross-tenant setups; alternatively, after verification, handlers must independently re-derive and enforce that the authenticated organization matches the organization owning the target repository/commit.
- `StatusHandler#process` (and any other handler that mutates records by SHA/ID without deriving them from `repository.full_name`) must scope its query to the repository provided in the payload, resolved to a `Repository`/`Stack` belonging to the *same* organization that authenticated the request, e.g. `Repository.from_github_repo_name(payload.dig('repository','full_name'))` intersected with `repository_owner`.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config), and a stack tracking a commit `SHA_TARGET` under `OrgB/target-repo`.
2. As an attacker who legitimately administers the GitHub App for `OrgA` (and thus knows `OrgA`'s `webhook_secret`), craft:
```json
{
  "sha": "SHA_TARGET",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/irrelevant" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner => "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the HMAC matches, so the request passes verification.
5. `StatusHandler#process` runs `Commit.where(sha: "SHA_TARGET")` — matching the `OrgB` commit — and calls `create_status_from_github!`, creating a `success` `Status` on it, which schedules continuous delivery / merges for `OrgB`'s stack, despite the attacker having no relationship to `OrgB`.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
