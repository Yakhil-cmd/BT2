Confirmed: the codebase supports multi-organization/multi-app configurations (as shown in `test/dummy/config/secrets_double_github_app.yml` with `OrgOne` and `OrgTwo` each having distinct `webhook_secret`), and `Shipit::StatusHandler` triggers real production deploys through `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → `Stack#trigger_deploy`, based purely on `Commit.where(sha: params.sha)` with no re-validation that the commit's owning stack/repository matches the organization whose secret validated the signature.

### Title
Webhook signature validated against `repository.owner.login`/`organization.login` while handlers act on unrelated `repository.full_name`/`sha` fields, enabling cross-organization webhook forgery leading to unauthorized deploys - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a field derived from the untrusted JSON payload itself (`repository.owner.login` or a fallback `organization.login`). The event handlers, however, act on entirely different payload fields — `repository.full_name` (used to resolve the target `Repository`/`Stack`) and top-level `sha` (used to resolve the `Commit`) — that are never checked for consistency with the organization whose secret validated the request. On a multi-tenant Shipit install (multiple GitHub Apps/organizations configured, as supported and tested via `test/dummy/config/secrets_double_github_app.yml`), a party who knows the `webhook_secret` for *any one* configured organization can forge a signed payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` / `sha` reference a *different* organization's repository/commit, causing Shipit to act on that unrelated stack.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

The signature check picks the correct HMAC secret for `repository_owner` and validates that the caller knows *that org's* secret. It does not, and cannot, guarantee anything about `repository.full_name` or `sha`, which are independent JSON fields under attacker control. Once the signature passes (because the request was actually signed with `OrgA`'s known secret), `create` dispatches to handlers purely based on those other, unchecked fields:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Shipit::Webhooks::Handlers::StatusHandler` is the clearest reachable sink — it resolves target commits purely by `sha`, globally, with no repository/org scoping at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Creating a `success` status triggers `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` if the target stack has continuous deployment enabled: [5](#0-4) [6](#0-5) 

That job ultimately calls `Stack#trigger_continuous_delivery` → `trigger_deploy`, which builds and runs a real `Deploy` task against the target stack's actual repository via `PerformTaskJob`: [7](#0-6) 

The equality the code implicitly (and incorrectly) assumes is:
`organization authenticated by verify_signature (repository.owner.login) == organization that owns the repository/commit acted upon by the handler (repository.full_name / commit.sha)`

This equality is never enforced. Any org configured in `Shipit.github` (see multi-org support: `test/dummy/config/secrets_double_github_app.yml` with distinct `webhook_secret` per org) can be used to sign a payload whose action-relevant fields target a different org's stack.

### Impact Explanation
On a Shipit install onboarding multiple GitHub organizations (a documented, tested configuration), an attacker who legitimately controls the GitHub App/webhook secret for their own onboarded organization (`OrgA`) can forge signed `status` webhook events referencing a commit `sha` that belongs to a different onboarded organization's (`OrgB`) stack. If that `OrgB` stack has `continuous_deployment` enabled, this can cause Shipit to autonomously trigger and run a real deploy task (`PerformTaskJob`/`TaskExecutionStrategy::Default#run`) against `OrgB`'s repository/environment — an unauthorized deploy triggered entirely outside `OrgB`'s control, satisfying the Critical impact bar ("an unauthorized deploy"). Similar cross-org confusion is reachable via `PushHandler`/`CheckSuiteHandler`, which resolve `stacks` solely from the unchecked `repository.full_name`.

### Likelihood Explanation
Exploitability requires only knowledge of one legitimate organization's `webhook_secret` in a multi-tenant Shipit deployment — no GitHub App private key, no `ApiClient` token, and no privileged Shipit account is needed. Any organization admin (or anyone who can read that org's webhook configuration) already possesses this secret for entirely legitimate reasons (configuring their own org's GitHub App webhook), so the barrier to constructing the forged cross-org payload is low, and the vulnerable code paths (`WebhooksController`, `Handler#repository_name`, `StatusHandler`) are unconditionally reachable by any POST to the shared `/webhooks` endpoint.

### Recommendation
Bind the identity used for signature verification to the identity acted upon: after determining `repository_owner` for secret selection, re-derive and cross-check that the same organization owns `repository.full_name` (and, for `StatusHandler`, scope the `Commit` lookup to stacks belonging to `Repository.from_github_repo_name(repository_name)` rather than a bare `Commit.where(sha: ...)` across all stacks/organizations).

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an admin with legitimate access to `OrgA`'s GitHub App webhook secret, craft a `status` event JSON body:
```json
{
  "sha": "<sha-of-a-commit-belonging-to-OrgB/production-stack>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/decoy-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s app, and successfully verifies the signature since it was computed with `OrgA`'s real secret.
5. `StatusHandler#process` ignores `repository.full_name` entirely and updates `Commit.where(sha: params.sha)`, which matches the `OrgB` commit — creating a `success` status on `OrgB`'s stack and (if `continuous_deployment` is enabled there) triggering an unauthorized real deploy.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
