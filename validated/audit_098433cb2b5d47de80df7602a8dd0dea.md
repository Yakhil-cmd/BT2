### Title
Cross-repository status forgery bypasses org/repository binding to trigger an unauthorized continuous deployment - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate a webhook from an attacker-supplied field in the *unverified* payload (`repository.owner.login`, or `organization.login`), then dispatches the same payload to event handlers. The `status` event handler, however, never re-checks which repository the authenticated payload actually claims to belong to: it matches commits **globally by `sha`** across the entire Shipit instance. This breaks the binding "organization that authenticated == repository that is written," letting a webhook that is valid for one (possibly low-security) organization/repository push a CI status onto a commit belonging to an entirely different stack/repository, and thereby trigger continuous deployment for it.

### Finding Description
`verify_signature` picks the GitHub App config to validate against using data taken straight from the JSON body, before any signature check occurs: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization — a supported, documented configuration (`webhook_secret: # nil`): [3](#0-2) [4](#0-3) 

Once the request passes this check, `WebhooksController#create` dispatches the *entire* raw payload to the registered handlers for the event type: [5](#0-4) 

The `status` handler, unlike `PushHandler` or the `pull_request` handlers (which scope work through `Repository.from_github_repo_name(params.repository.full_name)`), does not require or use any repository field at all — it looks up commits by `sha` across the whole database: [6](#0-5) 

Contrast this with `Handler#stacks`/`#repository_name`, which other handlers use to scope by repository — a scoping the `StatusHandler` skips entirely: [7](#0-6) 

Applying the matched status feeds directly into continuous-deployment scheduling: [8](#0-7) [9](#0-8) [10](#0-9) 

**The broken binding, stated as an equality that fails to hold:**
`organization used to select/verify the webhook secret (repository.owner.login in the payload)` ≠ `repository/stack whose commit status is actually mutated (any Stack whose Commit#sha matches, chosen with no repository check at all)`.

### Impact Explanation
An attacker who can get a `status` webhook signed/accepted for *any* organization configured in this Shipit instance (e.g., one configured without a `webhook_secret`, or one for which they legitimately control a repo with the app installed) can forge a `state: "success"` status for a commit `sha` belonging to a completely different, unrelated Stack/repository tracked by the same Shipit deployment. If that target stack has `continuous_deployment: true`, this becomes an **unauthorized deploy** — the qualifying impact explicitly listed as Critical in the rules — achieved purely by exploiting the mismatch between the authentication scope (organization) and the mutation scope (global commit lookup by sha), with no repository write access, session, or `ApiClient` token required.

### Likelihood Explanation
Requires: (a) a multi-org (or multi-repository) Shipit installation, (b) knowledge that at least one configured organization has no `webhook_secret` (a documented, supported configuration) or possession of a legitimate signed webhook from a repository the attacker controls, and (c) a target commit `sha` that also exists (or can be engineered to exist, e.g. via cherry-pick/rebase reproducing an identical commit) in the victim stack. This is non-trivial but realistic in shared/multi-tenant Shipit deployments, matching the "Medium-but-concrete, predictable given the circumstances" character of the source finding, while the impact here (unauthorized deploy) is more severe than the DoS in the original report.

### Recommendation
Bind the webhook-authenticated organization/repository to the object being mutated: require and validate `repository.full_name` (or `repository.owner.login`) in `StatusHandler` (and any other handler operating on cross-stack lookups), and scope `Commit` lookups through `Repository.from_github_repo_name(...).stacks` the same way `PushHandler`/`Handler#stacks` already do, rejecting any status payload whose declared repository does not match the repository actually associated with the matched commit's stack.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (no `webhook_secret`) and `orgB` (tracks the victim stack with `continuous_deployment: true`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/whatever" },
  "sha": "<sha of a pending/undeployed commit in orgB's stack>",
  "state": "success",
  "context": "ci/forged"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured) — request accepted regardless of any `X-Hub-Signature` header.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the orgB commit (no repository check), and calls `create_status_from_github!`, setting state to `success`.
5. `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` fires and deploys the commit on orgB's stack — an unauthorized deploy triggered by a webhook that never authenticated against orgB at all.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L1-16)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/deploy.rb (L327-331)
```ruby
    def schedule_continuous_delivery
      return unless stack.continuous_deployment?

      ContinuousDeliveryJob.perform_later(stack)
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
