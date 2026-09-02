This confirms the finding: `StatusHandler#process` looks up commits globally by SHA with no repository scoping, unlike `CheckSuiteHandler` and `PushHandler` which properly scope through `stacks` (derived from `repository_name`).### Title
`Webhooks::Handlers::StatusHandler` writes commit status by global SHA lookup, breaking the binding between the GitHub organization that signed the webhook and the repository whose commit is mutated - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook against based solely on `repository_owner`, a value taken from the untrusted JSON payload (`params.dig('repository','owner','login')` or `organization.login`), and resolves the corresponding GitHub App/organization via `Shipit.github(organization: repository_owner)`. Once the signature check passes for *that* organization, `StatusHandler#process` performs the actual mutation using `Commit.where(sha: params.sha)` — a lookup with **no scoping to any repository or stack at all**. Any organization able to produce a validly-signed `status` webhook (i.e., any org actually configured in Shipit with its own legitimate webhook secret) can therefore write a fabricated commit status onto a commit belonging to a **different** organization's repository/stack, as long as it guesses or knows the target SHA (git SHAs are public).

### Finding Description
`WebhooksController` binds "who authenticated" to the organization named in the payload: [1](#0-0) [2](#0-1) 

That is: `verify_signature` fetches `Shipit.github(organization: repository_owner)` and verifies the raw body against **that organization's** `webhook_secret` via `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Once verification succeeds, `Shipit::Webhooks.for_event(event)` dispatches the *entire raw JSON body* to the registered handler(s) for that event type: [4](#0-3) [5](#0-4) 

For the `status` event, that handler is `StatusHandler`, which does not use `repository_name`/`stacks` (the scoping helper every other handler uses) at all — it looks up commits by a bare, global `Commit.where(sha:)`: [6](#0-5) 

Contrast this with the base `Handler` class's intended scoping mechanism, and with the sibling handlers `PushHandler` and `CheckSuiteHandler`, which correctly resolve `stacks` from `repository.full_name` in the payload before touching any records: [7](#0-6) [8](#0-7) [9](#0-8) 

`StatusHandler` is the only handler in the set that deliberately ignores `payload['repository']` and instead trusts `params.sha` in isolation to find the target `Commit` across the **entire installation**, then calls `commit.create_status_from_github!(params)`, which writes into `commit.statuses` for whatever stack that commit belongs to: [10](#0-9) 

This is the same class of trust-binding break as the report's analog: the report shows GitHub-App attestation (`registry.check`) and caller-policy checks (`ENTRYPOINT_ONLY`) authorizing a dispatch, but never binding the *executing module* to the *current owner* who authorized it — an authenticated identity (old owner) whose privileges silently apply to an unrelated new context (new owner's storage). Here, the *authenticated organization* (verified via its own webhook secret) has its payload applied to an *unrelated repository's commit* with no equality check that `commit.stack.repository.owner == repository_owner`.

### Impact Explanation
Commit status directly gates `Commit#deployable?` and the merge queue / CI-required-statuses logic: [11](#0-10) [12](#0-11) 

By forging a `status` webhook signed with **their own** organization's legitimate secret, and setting `sha` to the SHA of a commit belonging to a **victim** organization's stack, an attacker who controls any Shipit-registered GitHub organization can:
- Write a `success` status for a required CI context (`ci.require`) onto a victim stack's commit they do not own, satisfying `deployable?` and unblocking `schedule_continuous_delivery`, which can trigger an unauthorized deploy on continuous-deployment-enabled stacks (`stack.continuous_deployment? && stack.deployable?`), and
- This is a cross-repository write of GitHub-status-derived state that the target organization never authorized, matching the "cross-repository writes" / "unauthorized deploy" Critical impact bucket.

This does not require an `ApiClient` token, `webhook_secret` of the victim, repository write access to the victim repo, or any credential beyond an attacker-controlled GitHub organization already onboarded to the same Shipit instance — it only needs a validly signed webhook for the attacker's own org and knowledge of the target SHA (public in git history/GitHub API).

### Likelihood Explanation
Every organization configured in `Shipit.github_apps`/`config/initializers` (multi-org Shipit deployments are an explicit supported case, as evidenced by `Shipit.github(organization:)` selecting per-organization secrets) can independently produce validly signed `status` webhooks. No additional privilege beyond "controls one legitimate onboarded GitHub org/repo" is required, and target SHAs are public. This makes the likelihood high in any multi-tenant/multi-org Shipit deployment.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the requesting repository the same way `PushHandler`/`CheckSuiteHandler` do, e.g., replace `Commit.where(sha: params.sha)` with `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }` (using the inherited `stacks`/`repository_name` helper from `Handler`), so a webhook can only mutate commits belonging to the repository named in its own signed payload.

### Proof of Concept
1. Attacker controls (or registers) GitHub organization `attacker-org` with a legitimate Shipit webhook secret, and has at least one stack under `attacker-org` so `Shipit.github(organization: 'attacker-org')` resolves to a configured `GitHubApp`.
2. Attacker looks up (via public GitHub API) the SHA of the latest undeployed commit on victim stack `victim-org/victim-repo`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
   signed with `attacker-org`'s legitimate `webhook_secret` in `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and passes signature verification (it is a real, valid signature for that org).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (belonging to a different stack/org), and calls `create_status_from_github!`, writing a forged "success" status that can satisfy `victim-org/victim-repo`'s `ci.require` gate and unblock `deployable?`/continuous deployment for that unrelated stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
