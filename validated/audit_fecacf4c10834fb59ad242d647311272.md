### Title
Webhook signature is verified for the organization named in `repository.owner.login`, but the repository actually written to is selected from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
This mirrors the report's root cause: two different checks/actions operate on two different pieces of state that are assumed to be the same but aren't. In `TreasuryVesting`, the first loop consumed the amount that the second loop was supposed to act on. Here, the field used to select *which organization's secret verifies the request* is not the same field used to select *which repository/stack the request acts on*, breaking the intended binding "organization whose signature was verified == repository that gets mutated."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/organization config - and therefore the `webhook_secret` used to validate `X-Hub-Signature` - based on `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or `organization.login` as a fallback): [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the target organization has no `webhook_secret` configured: [3](#0-2) 

Once the request passes this check, every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the repository/stacks to mutate using `Handler#repository_name`, which reads a **different** JSON field of the same payload - `repository.full_name` - not `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

Because Shipit supports multi-organization configuration (`Shipit.github(organization:)` / `github_app_config`) with a per-organization, optional `webhook_secret` ("Webhook secret (optional)" per the setup docs), the binding the code implicitly assumes is:

`organization authenticated via repository.owner.login == organization that owns repository.full_name`

This equality is never enforced. An attacker who controls (or has been onboarded as) an organization in this multi-tenant Shipit instance whose `webhook_secret` is blank/unset can:
1. POST directly to `/webhooks` (no GitHub involved) with `X-Github-Event: push` (or `status`/`check_suite`/`membership`).
2. Set `repository.owner.login` (or `organization.login`) to their own, secret-less org, so `verify_signature` trivially returns `true` regardless of the `X-Hub-Signature` header sent (`return true unless webhook_secret`).
3. Set `repository.full_name` to `victim-org/victim-repo`, an entirely unrelated repository already registered with Shipit under a different, secret-protected organization.

`Handler#repository_name` and `Repository.from_github_repo_name` then resolve the victim's `Repository`/`Stack` using only `full_name`, with no re-check that `full_name`'s owner matches the organization whose secret was actually verified: [7](#0-6) 

### Impact Explanation
Depending on event type, this lets an attacker forge state-changing webhooks against a stack they do not control and have no relationship to:
- `push`: forces `Stack#sync_github` for an attacker-chosen `expected_head_sha`/branch on the victim stack.
- `status`: creates a `Status` record via `Commit#create_status_from_github!` for arbitrary shas/states/contexts on the victim's commits, which is exactly the kind of blocking/required status that gates whether a commit is deployable.
- `check_suite`: enqueues `RefreshCheckRunsJob` for the victim stack.
- `membership`: creates/removes `Team`/`Membership`/`User` records tied to `Shipit.github_teams` authorization.

Forging a passing CI `status` on a victim's commit can unlock deploy safety checks that gate an "unauthorized deploy," and forging `membership` events can affect `Shipit.github_teams` authorization - both align with the defined High/Critical impact categories (unauthorized deploy, escalation into `Shipit.github_teams` authorization). This requires no `webhook_secret`, no `ApiClient` token, and no GitHub session - only knowledge that an organization with a blank `webhook_secret` exists in the deployment (visible simply by being a legitimately onboarded, secret-less org, or by observing `422` vs pass/fail behavior across guessed org names).

### Likelihood Explanation
This requires: (a) a multi-organization Shipit deployment, and (b) at least one onboarded organization configured without a `webhook_secret` (explicitly documented as optional). Given that condition, exploitation needs only unauthenticated HTTP requests to a public `/webhooks` endpoint with attacker-controlled JSON - no credentials, no signature computation, no privileged access. The likelihood is therefore tied entirely to operator configuration, not to any additional attacker capability, and the vulnerable code path (mismatched fields between `verify_signature` and `repository_name`) is unconditionally present regardless of configuration.

### Recommendation
Bind the verified identity to the acted-upon resource instead of trusting two independently-read fields of the same untrusted payload:
- Derive the organization used for signature verification from the **same** field (`repository.full_name`'s owner segment) that `Handler#repository_name` uses, or
- After resolving `stacks`/`Repository` in the handler, assert that `Repository#owner` equals the organization whose `webhook_secret` was verified in `WebhooksController#verify_signature`, rejecting the request (422) otherwise.
- Alternatively, make `webhook_secret` mandatory for every configured organization so `verify_webhook_signature` can never short-circuit to `true`.

### Proof of Concept
Given a Shipit instance configured with two organizations, `attacker-org` (no `webhook_secret` set) and `victim-org` (has `webhook_secret`), and a `Stack` already registered for `victim-org/victim-repo`:

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```

`verify_signature` calls `Shipit.github(organization: 'attacker-org')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally, matching: [8](#0-7) 

`StatusHandler#process` then looks up `Commit.where(sha: params.sha)` for the commit belonging to `victim-org/victim-repo` (resolved via `repository.full_name` in `Handler#repository_name`), and calls `create_status_from_github!`, forging a passing status on a victim commit despite never possessing `victim-org`'s `webhook_secret`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
