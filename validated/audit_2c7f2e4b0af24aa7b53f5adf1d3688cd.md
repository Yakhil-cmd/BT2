### Title
Cross-repository forged `status` webhook flips `Commit#deployable?` for any tracked commit via unscoped SHA lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by SHA globally (`Commit.where(sha: params.sha)`) instead of scoping to the repository that authenticated the webhook, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`s) which use the `stacks` helper backed by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. This lets a `status` webhook whose signature is valid for one repository/organization write a `Status` row for a commit that belongs to a completely different stack, as long as the attacker knows/reproduces that commit's SHA, flipping `Commit#deployable?` and thus `UndeployedCommit#deploy_disallowed?` on the victim stack.

### Finding Description
The broken binding: the equality that should hold is `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Status` created from a webhook. It does not hold here.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the HMAC using `Shipit.github(organization: repository_owner)`, i.e. it authenticates that the request came from *some* organization/app Shipit trusts and that the payload's `repository.owner.login` matches that organization's webhook secret. It never checks that the named repository is the one owning the target commit.
- `Handler` base class provides a `stacks` helper that correctly scopes lookups to the repository named in the payload: [1](#0-0) 
- `CheckSuiteHandler` and `PushHandler` correctly use this scoping (`stacks.where(...)`): [2](#0-1) 
- `StatusHandler#process`, however, bypasses `stacks` entirely and queries `Commit` globally by SHA with no repository binding at all: [3](#0-2) 
- `commit.create_status_from_github!(params)` uses the commit's own (victim) `stack_id` to create the `Status`, so the forged record attaches correctly to the victim stack while its `state`/`context`/`description` are fully attacker-controlled: [4](#0-3) [5](#0-4) 
- This flips `Commit#deployable?`: [6](#0-5) 
- which flips `UndeployedCommit#deploy_disallowed?` (`!deployable? || !stack.deployable?`), the exact CI gate the question targets, and is also read by `Api::DeploysController#create` when `require_ci` is passed: [7](#0-6) 

Exploit request: attacker owns/controls a repository whose owning GitHub organization is the same one configured in `Shipit.github_apps` that also hosts `victim/prod` (a common real-world scenario — one GitHub App/webhook secret is typically installed org-wide across many repositories, and the attacker only needs *a* repository under that org to emit a validly-signed webhook, not push access to `victim/prod`). They send `POST /webhooks` with header `X-Github-Event: status`, `repository.full_name = "org/attacker-repo"`, and body `{ "sha": "<victim/prod commit sha>", "state": "success", "context": "ci/forged" }`, signed with the org's real webhook secret (which the attacker's own repo's GitHub App installation legitimately provides via their own repo's webhook delivery). Because `StatusHandler` never checks that `org/attacker-repo` is the repository that owns the target commit, `Commit.where(sha: ...)` matches the tracked `victim/prod` commit and a bogus `success` status is attached to it.

Existing guards fail to close this: `verify_signature` only authenticates "this org's shared secret produced this signature," not "this specific repository owns this specific commit." `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not repository ownership. No model validation ties `Status#stack_id`/`commit_id` back to the webhook's asserted repository.

### Impact Explanation
An attacker with a repository under the same GitHub organization as the victim stack can, without ever touching `victim/prod`, cause an unrelated repository's webhook to flip `Commit#deployable?` to `true` for a `victim/prod` commit that never passed real CI. This directly manipulates the human-facing safety indicator (`deploy_state`) and the `require_ci` guard in `Api::DeploysController#create`, enabling an unauthorized deploy decision to be socially engineered or programmatically bypassed — this is a cross-repository payload mutating another repository's commit/stack state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task"). It is repeatable against any tracked commit whose SHA the attacker knows (SHAs are frequently visible via GitHub UI/API even without write access) and any stack sharing the same GitHub App/org-level webhook secret as the attacker-controlled repo.

### Likelihood Explanation
Requires: (1) the attacker's own repository shares a webhook-signing organization with the victim's stack (a standard Shipit deployment where one GitHub App/org covers many repos), and (2) the attacker knows the target commit's SHA (readily discoverable). No Shipit session, API token, or GitHub write access to `victim/prod` is needed. The attacker only needs to be able to trigger a webhook delivery from a repository they own within the shared organization, or directly `POST /webhooks` with a signature it can produce (any repo webhook delivery under that org's app gives them the correctly-signed payload capability). This is a low-cost, fully repeatable attack per target SHA/stack.

### Recommendation
Refactor `StatusHandler#process` to use the same repository-scoped `stacks` helper as the other handlers, e.g. resolve commits via `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or explicitly verify `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`, rejecting/ignoring statuses whose asserted repository does not match the commit's actual stack repository.

### Proof of Concept
In a minitest (e.g. `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `victim_stack` for repository `"victim/prod"` and a `victim_commit` on it with no statuses (`victim_commit.deployable?` is `false`; `UndeployedCommit.new(victim_commit, index: 0).deploy_disallowed?` is `true`).
2. Build a webhook payload with `repository.full_name = "attacker/evil"`, `sha: victim_commit.sha`, `state: "success"`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing only the outer signature check, as is standard in existing webhook tests which stub `verify_signature`).
4. Assert:
   - Before: `assert_not victim_commit.deployable?` and `assert UndeployedCommit.new(victim_commit, index: 0).deploy_disallowed?`.
   - After: `assert victim_commit.reload.deployable?` and `assert_not UndeployedCommit.new(victim_commit, index: 0).deploy_disallowed?`, despite no webhook ever having been authorized for `"victim/prod"`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```
