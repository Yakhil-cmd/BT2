This confirms the exploit chain: `Commit#deployable?` at [1](#0-0)  gates on `success?`, which is derived from `Status` records created directly from webhook payload data via `StatusHandler#process` at [2](#0-1) , and `Stack#trigger_continuous_delivery`/`schedule_continuous_delivery` acts on that state to trigger real deploys at [3](#0-2)  and [4](#0-3) .

### Title
Webhook signature verified against `repository.owner.login` while the acted-upon repository is selected from the unrelated `repository.full_name` field, allowing cross-organization forgery of push/status/check_suite events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to verify the HMAC signature against using `repository.owner.login` (falling back to `organization.login`), while every webhook `Handler` subclass locates the `Stack`/`Repository` to act on using the completely separate `repository.full_name` field from the same JSON body. Nothing ties these two fields together, so a payload that is valid (HMAC-verified) for one configured GitHub organization can freely claim to be about a repository belonging to any *other* organization configured in the same Shipit instance.

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.yml` keyed by organization, as documented in `docs/setup.md`), each organization has its own `GitHubApp` instance with its own `webhook_secret`, obtained via `Shipit.github(organization: organization)` in `lib/shipit.rb`.

`WebhooksController#verify_signature` picks the app/secret to check against like this: [5](#0-4) [6](#0-5) 

The signature (`request.headers['X-Hub-Signature']`) is verified against `request.raw_post` using the secret belonging to whatever organization `repository.owner.login` (or `organization.login`) claims to be — but the *entire* raw body, including `repository.full_name`, is attacker-controlled data that only needs to be internally consistent with whichever secret is used, not consistent with itself.

Every event handler, however, resolves the actual target using `repository.full_name`, not `repository.owner.login`: [7](#0-6) 

For example `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all operate on `stacks` (or `Commit.where(sha:)` directly, with no repository check at all) derived from that field: [8](#0-7) [2](#0-1) [9](#0-8) 

`StatusHandler` is especially dangerous: it matches on `Commit.where(sha: params.sha)` globally across the whole database with **no repository filter at all**, so it doesn't even need `repository.full_name` to line up — any SHA that happens to exist as a `Commit` row for any stack, in any organization, can have an arbitrary status created for it via `create_status_from_github!`.

This breaks the intended trust binding: "the organization whose secret authenticated the request" ≠ "the repository/stack that is actually written to." The webhook body is a single blob signed as a whole; nothing enforces that `repository.owner.login` (used for authentication routing) is the owner segment of `repository.full_name` (used for the actual write).

### Impact Explanation
An attacker who can get a webhook payload signed for *any one* configured GitHub organization in a multi-org Shipit install (including an organization whose `webhook_secret` is left blank, which is an explicitly documented, supported configuration in `docs/setup.md` and `config/secrets.development.example.yml` — "Webhook secret (optional)") can:
- Forge a `status` event with `state: "success"` for a real commit SHA belonging to a stack under a *different* organization, directly flipping `Commit#deployable?` to true via `success?` at [1](#0-0) , which can trigger an unauthorized automatic deploy through `Stack#trigger_continuous_delivery`/`schedule_continuous_delivery`.
- Forge `push`/`check_suite` events that cause Shipit to sync/refresh check runs for stacks it does not control, polluting state or forcing spurious GitHub API calls using the app's real `GITHUB_TOKEN`.

This crosses the "unauthorized deploy" impact bar defined in scope, since it lets an unprivileged party with credentials for only one org influence deploy-gating state for stacks belonging to organizations they have no relationship to.

### Likelihood Explanation
Requires a multi-org Shipit installation, and knowledge of (or zero-secret status of) at least one configured org's webhook credentials — a legitimate, documented deployment shape, not a hypothetical misconfiguration. `StatusHandler`'s complete lack of any repository scoping on `Commit.where(sha:)` makes the highest-impact path (forging a passing status) reachable with no cross-field trickery needed beyond guessing/knowing a valid commit SHA, which is often public GitHub information.

### Recommendation
After determining `repository_owner` for signature-app selection, verify that the same field (or the owner segment of `repository.full_name`) matches the `Repository`/`Stack` actually being mutated before dispatching to handlers — reject the webhook if `repository.owner.login` doesn't match the owner of the `repository.full_name` (or the `Stack`'s configured `Repository#owner`) being acted upon. Additionally, `StatusHandler#process` should filter `Commit.where(sha:, stack: matching_stacks)` rather than searching all commits in the database irrespective of which organization's webhook secret verified the request.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-known or no `webhook_secret`) and `OrgB` (victim, hosting stack `OrgB/victim-repo`, commit `<sha>` pending CI).
2. POST to `/webhooks` with `X-Github-Event: status`, a signature computed with `OrgA`'s secret (or omitted if `OrgA` has no secret configured), and a body:
```json
{
  "sha": "<sha of a commit belonging to OrgB/victim-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/irrelevant" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and passes verification using `OrgA`'s secret/lack thereof.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `OrgB` commit regardless of the `repository` field in the payload — and creates a `success` status on it, potentially unblocking continuous delivery for `OrgB`'s stack.

### Citations

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
