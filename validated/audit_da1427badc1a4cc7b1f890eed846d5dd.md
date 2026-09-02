### Title
Webhook authentication binds only to organization, not to target repository — cross-repository commit-status forgery bypasses CI gate - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by selecting a GitHub App/secret using only `repository_owner` (`params.dig('repository','owner','login')`), but the handlers that actually act on the payload (`PushHandler`, `CheckSuiteHandler`, and especially `StatusHandler`) use a completely different, independently-controlled field of the same JSON body to decide what gets written. `StatusHandler` doesn't even scope by repository at all — it matches purely on commit `sha` across the entire `commits` table. This breaks the binding "organization whose signature was verified" == "repository/commit actually mutated," analogous to the reward-allocation report's core flaw where the value used to *authorize* an action diverges from the value used to *compute/act on* it.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App instance solely from `repository_owner`: [1](#0-0) [2](#0-1) 

That result only gates *which secret* is used for `verify_webhook_signature`; it never re-appears when the payload is later dispatched to handlers. The handler base class instead derives the repository to scope work from a **different** JSON field, `repository.full_name`: [3](#0-2) 

Nothing in the controller or the base `Handler` cross-checks that `repository.owner.login` (used for authentication) is a prefix of `repository.full_name` (used for the actual write). Worse, `StatusHandler` doesn't even use `repository_name`/`stacks` scoping at all — it looks up commits globally by SHA: [4](#0-3) 

If a Shipit deployment leaves `github.webhook_secret` unset — an explicitly documented, supported "optional" configuration — [5](#0-4) 
then `verify_webhook_signature` unconditionally returns `true` regardless of any signature header, for any organization: [6](#0-5) 

In that (documented, no-secret) configuration, `verify_signature` never actually authenticates anything — it only performs an organization lookup (`Shipit.github(organization: repository_owner)`) which raises `GithubOrganizationUnknown` only when the org name is unrecognized, not when the signature is wrong. An unauthenticated network client can therefore freely POST a `status` (or `push`/`check_suite`) event, freely choosing `repository.owner.login` to match any configured organization, while the actual "write" target — the commit `sha` for `StatusHandler`, or `repository.full_name` for `PushHandler`/`CheckSuiteHandler` — is a value that's never validated against that organization at all.

This is the direct analog of the reported bug: in `StakingContract`, the value used for the security-relevant computation (`totalStaked`) was decoupled from the value that should have gated it (stake per epoch), letting an attacker manipulate an unchecked side-channel to control reward allocation. Here, the value used to select/verify the authenticating credential (`repository.owner.login`) is decoupled from the value that determines what gets mutated (`sha` / `repository.full_name`), letting an attacker manipulate an unchecked side-channel field to control which commit/stack in the system is affected — including stacks/commits belonging to organizations completely unrelated to the one nominally "verified."

### Impact Explanation
`StatusHandler#process` writes a fabricated CI status onto any commit whose SHA is known to the attacker (git SHAs are public, visible via `git log`, GitHub UI, or PR pages) — regardless of which stack/repository/organization owns that commit: [4](#0-3) 

Forged "success" statuses satisfy the `ci.require` deploy gate that `deployable?`/CI-status checks rely on, enabling an **unauthorized deploy** to proceed on a commit that never actually passed CI — matching the "Critical: unauthorized deploy" impact tier. `PushHandler` and `CheckSuiteHandler` similarly let the attacker choose which `Stack` (via `repository.full_name`) triggers `sync_github`/`schedule_refresh_check_runs!`, letting an unprivileged party force GitHub-sync jobs for repositories/stacks they have no relationship with.

### Likelihood Explanation
Exploitability depends entirely on the `github.webhook_secret` configuration. Because it is documented as **optional**, deployments that follow the documented setup literally (omitting the secret) are, by design of `verify_webhook_signature`, fully open — no signature, credential, or session of any kind is required to reach `WebhooksController#create`, since `skip_before_action :verify_authenticity_token` and the controller does not otherwise gate access. This is a pure network-reachable, unauthenticated endpoint issue, not contingent on any leaked secret, private key, or privileged account.

### Recommendation
- In the `Handler` base class, derive the repository-scoping key from the same field(s) that `WebhooksController#verify_signature` used to select the authenticating GitHub App, and reject/ignore payloads where `repository.owner.login` doesn't match the owner segment of `repository.full_name`.
- In `StatusHandler`, scope the `Commit` lookup to the specific stack/repository identified by the verified organization/repository instead of a bare global `sha` match.
- Treat a missing `webhook_secret` as a hard misconfiguration warning at boot (or require it), since `verify_webhook_signature`'s `return true unless webhook_secret` effectively disables authentication.

### Proof of Concept
1. Deploy Shipit with a multi-org `github` config where at least one organization ("org-attacker") has `webhook_secret` unset (per documented "optional" setup), or, in single-secret mode, obtain the SHA of a target commit in a victim stack belonging to a different org (public info).
2. POST to `/webhooks` with `X-Github-Event: status`, and body:
```json
{
  "sha": "<victim-commit-sha-in-org-B-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "org-attacker")`; since that org has no `webhook_secret` configured, `verify_webhook_signature` returns `true` unconditionally — no valid signature required.
4. `StatusHandler#process` executes `Commit.where(sha: params.sha)` and calls `create_status_from_github!`, writing a forged "success" status onto the victim commit in org B's stack, regardless of the fact that authentication was only ever tied to "org-attacker".
5. The victim stack's CI-gated deploy path now treats the commit as deployable, enabling an unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
