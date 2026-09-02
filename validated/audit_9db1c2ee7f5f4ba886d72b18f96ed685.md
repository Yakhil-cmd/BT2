StatusHandler confirms the strongest impact path: it matches on `Commit.where(sha: params.sha)` globally (not scoped to a repository), so it isn't even limited to the forged repo's stack. This confirms the finding is valid and lets me finalize.

### Title
Webhook signature verified against attacker-chosen organization while the payload's `repository.full_name`/`sha` used for writes is unchecked, enabling cross-repository writes and CI-status forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using an attacker-controlled field from the *unverified* JSON body (`repository.owner.login`), but the handlers that act on the payload (e.g. `PushHandler`, `CheckSuiteHandler`, `StatusHandler`) resolve the target `Stack`/`Commit` from a *different*, equally attacker-controlled field (`repository.full_name`, or globally by `sha` with no repository scoping at all). There is no cross-check binding the organization whose secret validated the signature to the repository/commit the handler actually mutates.

### Finding Description
`verify_signature` picks the GitHub App config with: [1](#0-0) 
using: [2](#0-1) 
`repository_owner` is read straight from `JSON.parse(request.raw_post)` before the HMAC signature is checked — i.e. it is fully attacker-controlled at the time it's used to pick the secret. `verify_webhook_signature` then HMACs the *entire* raw body with that org's secret: [3](#0-2) 

Once verification passes, the actual event handlers resolve their target using unrelated fields of the same body:
- `Handler#stacks` looks up by `payload.dig('repository', 'full_name')`, independent of `repository.owner.login`: [4](#0-3) 
- `PushHandler#process` syncs commits for stacks matching that (attacker-chosen) `full_name`/branch: [5](#0-4) 
- `CheckSuiteHandler#process` schedules check-run refreshes for stacks resolved the same way: [6](#0-5) 
- `StatusHandler#process` is even less scoped — it updates **any** `Commit` row across the *entire installation* matching `params.sha`, with no repository/organization filter at all: [7](#0-6) 

This is the documented "Using Multiple GitHub Applications" scenario, where each org has its own `webhook_secret`: [8](#0-7) 

Equality broken: `organization that authenticated the signature` (`repository.owner.login` used in `verify_signature`) ≠ `repository/commit actually written to` (`repository.full_name` in `Handler#stacks`, or unscoped `sha` in `StatusHandler`).

### Impact Explanation
An attacker who controls (or is an administrator/collaborator of) any single GitHub organization/App configured on a shared multi-org Shipit instance knows that org's `webhook_secret` (it's an app-level secret they configured themselves, not privileged Shipit access). Using that known secret, they can craft a signed webhook whose `repository.owner.login` matches their own org (so `verify_signature` passes) but whose `repository.full_name` (for push/check_suite) or `sha` (for status, unscoped) targets a stack/commit belonging to a **different** organization/repository tracked by the same Shipit instance. This allows:
- Forging a `status` event to mark an arbitrary existing commit (in any repo tracked by the instance) as CI-passing via `create_status_from_github!`, which can satisfy `ci.require`/merge-queue/deploy gating checks — enabling an **unauthorized deploy or merge** of that commit.
- Triggering `GithubSyncJob`/check-run refreshes against another organization's stack.

This matches the "unauthorized deploy, rollback or merge" High-impact criterion, achieved purely by crossing an authentication boundary (org A's signature) into a write scope (org B's repo/commit) that was never covered by that signature.

### Likelihood Explanation
Requires the attacker to control at least one GitHub App/org already configured on the same shared Shipit deployment (multi-org setup, as documented) — a realistic scenario for shared internal Shipit instances serving many teams/orgs, but not applicable to single-org deployments. No Shipit session, API token, or GitHub write access to the victim repository is needed — only knowledge of one's own org's `webhook_secret` and the target repository's `full_name`/an existing tracked commit `sha` (both easily discoverable, e.g. via public GitHub).

### Recommendation
Bind signature verification to the same identity the handlers act on: verify the payload's `repository.full_name` (or `organization.login` for org-scoped events) resolves to a `Stack`/`Repository` that actually belongs to the organization whose secret validated the signature, before invoking any handler. At minimum, `StatusHandler` should scope `Commit.where(sha: ...)` to commits belonging to stacks under the verified organization, and `Handler#stacks`/`repository_owner` should be reconciled (e.g. re-derive `repository_owner` after verification from the same repository object used by the handler, and reject if the App used for verification isn't authorized for that repository).

### Proof of Concept
1. Attacker administers `OrgA`'s GitHub App on a shared Shipit instance and knows `webhook_secret_A`.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/decoy" },
  "sha": "<sha of a commit tracked under OrgB/target-repo>",
  "state": "success",
  "context": "ci/tests"
}
```
3. `X-Hub-Signature` is computed as `sha1=` HMAC-SHA1(`webhook_secret_A`, raw_body) — a secret the attacker legitimately possesses.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `OrgB/target-repo` commit regardless of `repository.owner.login` — and calls `create_status_from_github!`, forging a passing CI status on an unrelated organization's commit, potentially unlocking deploy/merge gating for that commit.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
