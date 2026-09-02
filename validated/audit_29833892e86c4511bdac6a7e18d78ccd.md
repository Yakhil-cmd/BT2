### Title
`check_suite` webhook accepted for a "no-secret" GitHub org lets an attacker trigger check-run refresh (DB writes) on an arbitrary victim stack via `repository.full_name` confusion - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook using the secret configured for `repository.owner.login`, but `Webhooks::Handlers::Handler#stacks` (used by `CheckSuiteHandler`) selects the target stack using the independent `repository.full_name` field of the same forged JSON body. Because these two fields are never checked for consistency, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has a blank `webhook_secret`, an attacker can pick any Shipit-configured org that has no secret to pass the signature check while pointing `repository.full_name` at a completely unrelated victim repository.

### Finding Description
The broken binding: the code implicitly assumes `repository.owner.login used for signature verification == repository.full_name used to select the affected stack`. In fact these are two independently attacker-controlled JSON fields with no cross-check.

- `WebhooksController#verify_signature` builds `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')`, and calls `github_app.verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank for that org's config — no HMAC is checked at all. [3](#0-2) 
- Once past this gate, `CheckSuiteHandler#process` calls `stacks`, defined in the base `Handler` class as `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name = payload.dig('repository', 'full_name')` — a completely separate field from `repository.owner.login`. [4](#0-3) [5](#0-4) 

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: check_suite`, body:
```json
{
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "check_suite": { "head_branch": "main", "head_sha": "<victim commit sha>" }
}
```
`verify_signature` resolves `Shipit.github(organization: "no-secret-org")`; since that org's config has no `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the signature header or body content (no HMAC required at all). The request passes `check_if_ping` and `drop_unhandled_event` (a `check_suite` handler is registered), then `CheckSuiteHandler.call(params)` runs, resolving `victim-org/victim-repo`'s stacks by `full_name` and, for any stack whose `branch` matches `head_branch`, finds `stack.commits.where(sha: head_sha)` and calls `schedule_refresh_check_runs!`, enqueuing `RefreshCheckRunsJob` for that commit. [6](#0-5) 

Existing guards fail here because: `drop_unhandled_event`/`check_if_ping` do not validate the payload's internal consistency; `verify_signature` only checks whether *some* configured org's secret matches (or is absent), and never re-derives or compares `repository.full_name`'s owner against `repository.owner.login`; and `ExplicitParameters` (`CheckSuiteHandler`'s `params do ... end` block) only validates the shape of `check_suite.head_sha`/`head_branch`, not `repository.full_name` versus `repository.owner.login`.

### Impact Explanation
The immediate effect is that `RefreshCheckRunsJob` is enqueued and executed for a stack/commit belonging to a repository the attacker never authenticated against — `stack.commits` and `Shipit::CheckRun` rows for the victim repository get written/updated as a side effect of `refresh_check_runs!`, which in turn calls `stack.github_api.check_runs(github_repo_name, sha, ...)` using the *victim's real, correctly configured* GitHub App credentials and repo name (derived from the resolved `Stack`/`Repository` record, not from attacker-controlled fields) . This is important nuance: the job pulls **real** GitHub check-run conclusions for the real repository (it does not let the attacker forge arbitrary `blocked?`-triggering conclusions), so the "forced status" claim in the question is only partially realized — the attacker cannot inject fabricated CI conclusions this way, but they *can* force the app to schedule authenticated GitHub API calls and write/update `CheckRun` DB rows for an arbitrary tracked stack/repository of their choosing, using no credentials of their own and needing only the existence of one "no-secret" org configured anywhere in Shipit. This is a genuine confused-deputy / cross-tenant authorization bypass (a webhook body for one "identity" causing effects scoped to a different repository) and matches the Critical category "a payload for one repository mutating another's stack, commit, task or team," though the actual data written is legitimate upstream GitHub state rather than attacker-forged content.

### Likelihood Explanation
Preconditions: at least one GitHub org/app configured in `Shipit.secrets.github` with a blank `webhook_secret` (the "no-secret organization" gap), and a victim stack tracked by Shipit with `blocking_statuses` configured and a known branch/commit SHA. The attacker needs no Shipit session, API token, or GitHub credentials — only the ability to send an HTTP POST to `/webhooks` and knowledge of a victim repo's `full_name`, branch, and a commit SHA (all discoverable from GitHub's public API or the victim's public repo). This is fully repeatable against any tracked stack, for any commit SHA, as often as desired.

### Recommendation
Bind the authenticated identity to the payload's operative repository field before dispatching to handlers: after `verify_signature` succeeds, re-derive the organization from `repository.full_name` (or `repository.owner.login` consistently) and reject the event if that organization's resolved config differs from the one that produced a valid/blank signature. Additionally, treat a blank `webhook_secret` as a misconfiguration to warn/reject on rather than an automatic pass, or require an explicit opt-in flag (e.g., `insecure: true`) for orgs allowed to skip verification, and always ensure `repository_name` used for `stacks` lookup in `Handler` matches the same repository whose secret validated the signature.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`), no live GitHub:
1. Configure `Shipit.secrets.github` (stub) with two orgs: `"no-secret-org"` (no `webhook_secret` key) and the victim org `"victim-org"` (with a real `webhook_secret`).
2. Create `victim_repo = shipit_repositories(:shipit)` (full_name `"victim-org/victim-repo"`), a `stack` on branch `"main"` with `cached_deploy_spec` containing `ci.blocking: ["soc/compliance"]`, and a `commit` with a known `sha`.
3. Assert binding before: no `RefreshCheckRunsJob` enqueued for `commit.id`.
4. POST to `/webhooks` with header `X-Github-Event: check_suite`, no `X-Hub-Signature` (or a garbage one), and body:
   ```json
   { "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"},
     "check_suite": {"head_branch": "main", "head_sha": "<commit.sha>"} }
   ```
5. Assert response is `200 OK` (not `422`).
6. Assert `RefreshCheckRunsJob` was enqueued with `commit_id: commit.id`, i.e. `assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit_id: commit.id])`.
7. This demonstrates the equality `repository_owner (used for auth) == effective target repository (used for effect)` is violated: the request was "authenticated" as `no-secret-org` (via blank secret) yet mutated state scoped to `victim-org/victim-repo`, which never validated the request.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L152-154)
```ruby
    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end
```
