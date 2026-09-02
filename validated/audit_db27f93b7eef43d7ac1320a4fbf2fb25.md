### Title
Webhook signature verification selects the HMAC secret from the unauthenticated payload, decoupling the organization that authenticates a delivery from the repository/organization the handlers actually write to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the Shipit-engine analog of the "unprotected slippage tolerance" bug class: a value that flows into a security-critical decision is taken from attacker-controlled input rather than from a source that was itself authenticated. Here the value is `repository_owner`, and the security-critical decision is *which organization's webhook secret is used to verify the incoming GitHub webhook signature*.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App configuration (and therefore the HMAC secret) to check the signature against using a field taken directly out of the still‑unverified JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository','owner','login')` (or `organization.login`) straight from `request.raw_post`, before any signature has been validated. `Shipit.github(organization: repository_owner)` then loads that organization's `webhook_secret` and verifies the `X-Hub-Signature` HMAC against it (`lib/shipit/github_app.rb#verify_webhook_signature`).

The handlers that subsequently act on the payload, however, key off *different* fields of the same untrusted body: `Handler#repository_name` uses `payload.dig('repository','full_name')` [3](#0-2) , `PushHandler` resolves stacks by `branch` only within whatever `stacks` that `repository_name` resolves to [4](#0-3) , `StatusHandler` looks up commits **globally by `sha`, with no repository/organization scoping at all** [5](#0-4) , and `MembershipHandler` creates/updates a `Team` using `params.organization.login` taken verbatim from the body [6](#0-5) .

The equality that should hold but is broken is:
`organization whose secret authenticated the HTTP signature == organization/repository the handler is permitted to mutate`.

Because `repository.owner.login` (used to pick the secret) and `repository.full_name` / `organization.login` (used to pick what gets written) are two independent, attacker-controlled fields of the same JSON body, an attacker who is a legitimate, onboarded GitHub organization in this multi-tenant Shipit install (i.e., they know or can trigger deliveries signed with *their own* organization's `webhook_secret`) can craft a payload where `repository.owner.login = "attacker-org"` (so the signature check passes using attacker-org's own secret) while `repository.full_name`, `organization.login`, or `sha` reference a completely different organization's stack/commit.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" bar:
- Via `StatusHandler`, a validly-signed (by the attacker's own org secret) forged `status` event can set an arbitrary commit status (`state: success`) on any commit `sha` in the entire installation, regardless of which organization/repository actually owns that commit — because `Commit.where(sha: params.sha)` is not scoped to the authenticating organization. This can flip a `required_statuses`/blocking status used by `DeploySpec` to gate deploys, producing an unauthorized deploy on a stack the attacker has no relationship to.
- Via `MembershipHandler`, a payload signed with the attacker's own organization secret can create/update `Team` records carrying an arbitrary `organization` string and add arbitrary GitHub logins as members of that team, which is the mechanism used elsewhere for team-based OAuth authorization (`oauth_teams` in `lib/shipit/github_app.rb`). This raises a plausible escalation path into `Shipit.github_teams` authorization.
- Via `PushHandler`, forged push events can trigger `stack.sync_github` for stacks under a branch name shared with another organization's repository.

### Likelihood Explanation
Requires the attacker to be an onboarded/legitimate organization within a multi-tenant Shipit deployment (i.e., they must be able to get one valid `webhook_secret` for at least one organization configured in the instance, which is the normal, low-privilege state for any customer onboarded to a shared Shipit install). No repository write access, API token, or session is required — this is exactly the "unprivileged attacker breaks a deployment-trust binding" pattern described in the rules, using only a webhook signing capability for their own, unrelated organization.

### Recommendation
Bind signature verification and payload interpretation to the same, single source of truth:
- Verify the signature first against the organization/app config resolved from the stack/repository the handler is about to touch (i.e., resolve `repository_name`/target stack, look up which org owns *that* repository server-side, and only then pick the corresponding `webhook_secret`), instead of trusting `repository.owner.login` from the body to select the verification key.
- In `StatusHandler`, scope the `Commit.where(sha: ...)` lookup to commits belonging to stacks under the same, already-verified organization/repository as the webhook delivery.
- In `MembershipHandler`, cross-check `params.organization.login` against the organization actually used to verify the signature and reject mismatches.

### Proof of Concept
1. Attacker administers/onboards `attacker-org` in the shared Shipit instance and knows its `webhook_secret` (e.g., they can freely trigger and observe webhook deliveries for their own org).
2. Attacker crafts a `status` event JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
  "sha": "<sha of a commit belonging to victim-org/stack>",
  "state": "success",
  "context": "required-ci-check"
}
```
3. Attacker signs the raw body with `attacker-org`'s `webhook_secret` and sends it with `X-Github-Event: status` and the resulting `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`), which succeeds because the signature really was produced with `attacker-org`'s own secret.
5. `StatusHandler#process` then runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of organization — and calls `create_status_from_github!`, marking a required status green on a stack the attacker never had signature/write access to, which can unblock an otherwise-blocked deploy on `victim-org`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-42)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
```
