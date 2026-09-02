This is exactly the analog the report describes: the field the code trusts as the "signed" authority (`repository.owner.login`, used only to select which organization's webhook secret verifies the HMAC) is never actually bound to the field the handlers act on (`repository.full_name`, used to look up the `Repository`/`Stack` to write to).

### Title
Webhook signature verification is keyed on `repository.owner.login` while push/status/check_suite handlers act on the unrelated, unverified `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), but the handlers that actually perform the write (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`) resolve the target `Stack` using `payload.dig('repository', 'full_name')` via `Handler#repository_name`. These two payload fields are never checked against each other.

### Finding Description
`verify_signature` computes `repository_owner` purely to pick which `GitHubApp` (and thus which `webhook_secret`) to use for `verify_webhook_signature`: [1](#0-0) [2](#0-1) 

Once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches the *raw* JSON payload to handlers, and the base `Handler` class resolves the affected repository/stacks using an entirely different field, `repository.full_name`: [3](#0-2) 

`PushHandler#process` then updates any stack whose `Repository.from_github_repo_name(repository_name)` matches, using `params.after` (the pushed SHA) with no further cross-check against `repository.owner.login`: [4](#0-3) 

Because the HMAC signature covers the entire raw request body (`request.raw_post`), an attacker cannot forge an arbitrary payload without knowing the correct `webhook_secret` for **some** organization. However, if the app is configured for multiple organizations (`Shipit.github(organization: ...)` per-org secrets, as documented for multi-org setups), any org that legitimately possesses its own valid `webhook_secret` (e.g. a low-trust/sandbox org onboarded to the same Shipit instance) can send a signed webhook whose `repository.owner.login`/`organization.login` names *that org* (satisfying signature selection) while `repository.full_name` names a *stack belonging to a completely different organization/repository* tracked by the same Shipit instance. The signature check only proves "this request was signed with Org A's secret"; it proves nothing about which `repository.full_name` the payload is allowed to reference, because that field is outside the binding the check enforces (a payload field acted upon but never covered by the verified check).

### Impact Explanation
This breaks the intended binding: `organization that authenticated == repository that is written`. A holder of one organization's `webhook_secret` can trigger `GithubSyncJob`, commit-status creation, or `RefreshCheckRunsJob` against a stack tracking a *different* organization's repository, by simply setting `repository.full_name` to the victim repo while keeping `repository.owner.login`/`organization.login` equal to their own org. This can drive an unauthorized deploy: `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)`, and forged/spoofed `status`/`check_suite` events can also flip CI-status gating that feeds `MergeRequest`/deploy readiness checks used elsewhere in the engine (`Shipit::MergeRequest#all_status_checks_passed?`), potentially unlocking an unauthorized deploy on a stack the attacker's org has no legitimate relationship to.

### Likelihood Explanation
Requires the Shipit instance to be configured with multiple GitHub organizations sharing one deployment (explicitly documented and supported: `docs/setup.md` "Using Multiple Github Applications"), and requires the attacker to control/administer one of those organizations' GitHub Apps (to know its `webhook_secret`) while targeting a stack belonging to another configured organization. This is a realistic multi-tenant misconfiguration scenario the engine explicitly supports, not a theoretical one; no session, `ApiClient` token, or GitHub App private key is needed—only the webhook secret of one already-onboarded low-trust organization.

### Recommendation
After signature verification, cross-check that `repository.owner.login` (or `organization.login`) used to select the verifying secret matches the owner recorded on the `Repository`/`Stack` resolved via `repository.full_name` in `Handler#stacks`, rejecting the webhook if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per the documented multi-org config).
2. As an admin of `attacker-org`'s GitHub App, craft a `push` webhook JSON body with:
   - `repository.owner.login` = `"attacker-org"` (so `verify_signature` picks `attacker-org`'s secret)
   - `repository.full_name` = `"victim-org/victim-repo"` (the repo actually acted upon)
   - `ref` = `"refs/heads/master"`, `after` = attacker-chosen SHA
3. Sign the raw body with `attacker-org`'s known `webhook_secret` and send it to `/github/webhooks` with the correct `X-Hub-Signature`.
4. `verify_signature` succeeds (signature matches `attacker-org`'s secret for `repository_owner == "attacker-org"`).
5. `PushHandler#process` resolves stacks via `repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)`, triggering a sync/deploy pipeline action on a stack the attacker's organization does not own, despite passing signature verification tied to the attacker's own org.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
