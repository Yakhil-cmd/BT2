### Title
Webhook Signature Verification Is Bound to `organization`/`repository.owner.login`, But Repository Selection Uses Unchecked `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App credentials for the organization derived from the payload (`repository.owner.login` or `organization.login`), but every `Handler` subclass selects which `Stack`/`Repository` to mutate using a *different* field of the same attacker-supplied JSON body: `repository.full_name`. Nothing ties these two values together, so a correctly-signed payload for organization A can carry a `repository.full_name` pointing at a repository owned by organization B, and the handler will happily act on B's stack.

### Finding Description
Signature verification uses only the organization/owner login: [1](#0-0) [2](#0-1) 

Once the signature check passes, the raw parsed JSON is dispatched unmodified to every registered handler for the event: [3](#0-2) 

Every handler picks the target repository/stacks from a completely separate field of the same payload, `repository.full_name`, with no cross-check against the field used for signature verification: [4](#0-3) 

Concrete handlers then mutate state for whatever stacks that lookup resolves to, e.g. syncing GitHub history: [5](#0-4) 

or creating commit statuses that drive deploy gating: [6](#0-5) 

or scheduling check-run refreshes: [7](#0-6) 

This is structurally the same bug class as the external report: the code verifies one identity (the proposal id / here, the signing organization) but acts on a second, independently-controlled field (the request's proposal / here, `repository.full_name`) without ever checking they are the same entity. The binding that should hold — "the organization whose secret signed the request" == "the repository being written" — is never enforced.

### Impact Explanation
An attacker who legitimately administers (or has a valid, correctly configured GitHub App/webhook secret for) one organization/repository tracked by this Shipit instance can forge a raw HTTP POST to `/webhooks`, sign it with their own organization's valid secret, but set the JSON body's `repository.full_name` to a *different, victim* organization's tracked repository. Because `verify_signature` only checks the signer against `repository.owner.login`/`organization.login` and never cross-validates it against `repository.full_name`, the forged event is accepted and dispatched to handlers that operate on the victim's `Stack`. This allows:
- Injecting a fabricated `push`/`status` event to mark an arbitrary commit on the victim's repository as CI-green (`StatusHandler` → `Commit#create_status_from_github!`), which feeds directly into `Stack#next_commit_to_deploy`/`deployable?` and can trigger continuous-delivery auto-deploys of that commit.
- Forcing `PushHandler` to resync the victim stack against an attacker-chosen `expected_head_sha`.

This is a cross-repository write / unauthorized-deploy-enabling primitive achieved purely by forging webhook payload fields, without ever obtaining credentials for the victim organization, matching the "cross-repository writes" / "unauthorized deploy" impact tier.

### Likelihood Explanation
Requires that the attacker control (or have valid signing credentials for) at least one organization/repository already onboarded into the same Shipit instance — a scenario explicitly anticipated by the multi-GitHub-App configuration support in this codebase (`Shipit.github(organization:)`, multiple app secrets). No repository write access, no Shipit session, and no `ApiClient` token are needed — only the ability to compute an HMAC signature valid for one tracked organization and to POST directly to the public `/webhooks` endpoint with a crafted body.

### Recommendation
In `WebhooksController`/`Handler`, after verifying the signature for `repository_owner`, assert that the resolved `Repository`'s owner (or the `Stack`'s configured GitHub organization) matches the organization whose credentials verified the signature, before dispatching to handlers. Reject the webhook if `repository.full_name`'s owner segment does not match `repository.owner.login`/`organization.login` used in `verify_signature`.

### Proof of Concept
1. Onboard/administer organization `attacker-org/attacker-repo` in the target Shipit instance and obtain a validly signed webhook delivery capability for it (per Shipit's multi-GitHub-App support).
2. Craft a raw JSON body for a `status` (or `push`) event:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Compute `X-Hub-Signature` with `attacker-org`'s webhook secret over the raw body, and set `X-Github-Event: status`.
4. POST to `/webhooks`. `verify_signature` resolves `repository_owner` from `repository.owner.login` = `attacker-org` and passes; `StatusHandler#process` then looks up commits solely via `sha` regardless of any owner mismatch, or for handlers using `Handler#stacks`, resolution is via `repository.full_name` = `victim-org/victim-repo`, causing the fabricated status/sync to be applied to the victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
