### Title
Webhook signature only authenticates the payload's declared organization, not the repository the event is applied to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the `X-Hub-Signature` against using `repository.owner.login` (falling back to `organization.login`) taken directly from the untrusted request body. `Webhooks::Handlers::StatusHandler`, however, applies the event's effect (writing a commit status) using only `params.sha`, matched globally against `Commit.where(sha: ...)` with no check that the commit's stack/repository belongs to the same organization/owner that produced a valid signature.

### Finding Description
The binding that should hold is: *organization whose secret signed the payload == organization owning the repository/commit the event mutates*. Instead:
- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . This confirms only that the sender knows the webhook secret configured for whatever organization login is *stated* in the JSON body.
- `StatusHandler#process` then updates commit status for **any** commit in the entire installation whose SHA matches `params.sha`, with zero scoping to the organization/repository that was actually verified: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .
- The generic `Handler` base class does derive a `repository_name` from `payload.dig('repository','full_name')` [4](#0-3) , but `StatusHandler` never calls `stacks`/`repository_name` — it bypasses that scoping entirely and queries `Commit` directly by SHA across the whole database.

Because SHA-1 git hashes are effectively global identifiers (not namespaced to an owner), an attacker who is a legitimate GitHub org admin for *any* org onboarded into this Shipit instance (and therefore knows/controls that org's webhook secret, e.g. an org where they can create a repo and its webhook, or trigger a manufactured `status` event under `organization.login`) can:
1. Craft a `status` webhook body with `repository.owner.login` set to their own org (so `verify_signature` validates against their own, legitimately-known secret) and `sha` set to a commit SHA that actually belongs to a victim's stack/repository in a completely different, unrelated organization.
2. Sign the raw body with their own org's webhook secret and POST it to `/webhooks`.
3. `verify_signature` passes because the signature genuinely matches the secret for the attacker's own organization.
4. `StatusHandler` then finds and mutates the victim's `Commit` (matched purely by SHA) via `create_status_from_github!`, injecting a forged CI status (e.g. `success`) for a commit under a completely different organization/repository than the one whose secret signed the request.

This breaks the intended binding "the organization that authenticated == the repository whose state is written," matching the analog to the reported bug class (a value used for a critical decision that isn't bound/validated against what was actually verified).

### Impact Explanation
A forged, incorrectly-scoped `success` status can flip `Commit#deployable?` to `true` for a victim stack (`deployable? => !locked? && (stack.ignore_ci? || (success? && !blocked?))`, `add_status` triggers `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges`) [5](#0-4) [6](#0-5) . If the victim stack has `continuous_deployment?` enabled, this can lead to `ContinuousDeliveryJob` deploying a commit whose real CI status was never green — i.e., an unauthorized/unsafe deploy triggered by a party with no relationship to that repository, satisfying the "unauthorized deploy" high/critical impact bar.

### Likelihood Explanation
Requires the attacker to control (own/administer) at least one GitHub organization/repository that is legitimately connected to this Shipit instance (so they know that org's own webhook secret) — this is a realistic scenario in multi-tenant or open-organization Shipit deployments where many orgs/teams self-service configure webhooks. No access to the victim's secrets, `GITHUB_TOKEN`, or Shipit session is required, only knowledge of a SHA that exists in the victim's stack (obtainable from any public GitHub activity, PR, or commit link).

### Recommendation
In `StatusHandler` (and any other handler that queries data independent of `payload['repository']`), scope the effect to the same repository that produced the verified organization, e.g. restrict `Commit.where(sha: params.sha)` to `Commit.joins(:stack => :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner_from_payload })`, or better, resolve the target repository via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and only operate on commits belonging to that repository's stacks — mirroring what `Handler#stacks` already does for other handlers. More generally, `WebhooksController#verify_signature` should assert that every identifier used later to select a target record (repository, stack, commit) is consistent with the very same `repository.owner.login`/`organization.login` value used to select the verification secret.

### Proof of Concept
1. Setup: Shipit instance configured with two onboarded GitHub orgs, `attacker-org` (attacker is admin, knows its `webhook_secret`) and `victim-org` (has a stack tracking commit `abcdef123...` currently pending/failing CI).
2. Attacker builds JSON body:
```json
{
  "sha": "abcdef123...",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(attacker-org secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature against the attacker's own known secret [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: 'abcdef123...')`, finds the commit belonging to `victim-org`'s stack (unrelated to `attacker-org`), and calls `create_status_from_github!` to record a forged `success` status [3](#0-2) .
6. If `victim-org`'s stack has continuous deployment enabled and this was the last blocking status, the commit becomes `deployable?` and can be auto-deployed — an unauthorized deploy triggered entirely by an attacker with no credentials or relationship to `victim-org`.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
    end
```
