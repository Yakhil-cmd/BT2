### Title
Cross-organization commit-status forgery bypasses the org-to-repository trust binding in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate a GitHub webhook based on `repository.owner.login` (or `organization.login`) from the JSON body, then verifies the raw payload against that organization's `webhook_secret`. That verification only proves "this payload was signed by *some* org configured in Shipit," it does not bind the signing organization to which repository/stack the payload is allowed to mutate. `StatusHandler#process` mutates state by looking up commits solely by `sha` across the *entire* `Commit` table, with no scoping to the repository/organization that produced the signature. This breaks the intended binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to check the signature against using `repository_owner`, which is read straight from the JSON body: [1](#0-0) [2](#0-1) 

Once the HMAC over the raw body is valid for whatever organization `repository.owner.login` claims to be, the request is dispatched to handlers with the full, attacker-controlled JSON body: [3](#0-2) 

`StatusHandler`, however, does not use the base `Handler#stacks`/`repository_name` scoping (which filters by `payload.dig('repository', 'full_name')`) at all. It resolves target commits purely by the `sha` field, globally: [4](#0-3) 

Because `repository.owner.login` (used to select the signing secret) and `sha` (used to select which commit/stack gets mutated) are two independent, attacker-controlled fields in the same JSON body, they can be set inconsistently without invalidating the signature — the signature only covers the raw bytes, not any internal cross-field consistency. In a multi-org deployment (`Using Multiple Github Applications`, documented in `docs/setup.md`), each org has its own `webhook_secret`: [5](#0-4) [6](#0-5) 

An organization admin who legitimately knows only their own org's `webhook_secret` (because they configured the GitHub webhook for their own org/repo) can therefore forge a `status` event: set `repository.owner.login` to their own org (so `Shipit.github(organization: repository_owner)` picks their own secret and the HMAC verifies), but set `sha` to a commit belonging to a *different* org's stack. `StatusHandler#process` will find that commit and call `commit.create_status_from_github!(params)`, creating a real `Status` record on someone else's stack/commit: [7](#0-6) 

### Impact Explanation
Creating a `Status` triggers real side effects on the *victim* stack that the attacker does not own or control:
- `enable_ci_on_stack` flips `commit.stack.enable_ci!` on the target stack.
- `schedule_continuous_delivery` invokes `commit.schedule_continuous_delivery`. [8](#0-7) [9](#0-8) 

If the victim stack has continuous deployment enabled, forging a "success" status on the next undeployed commit can cause `ContinuousDeliveryJob` to actually trigger a deploy of that stack: [10](#0-9) [11](#0-10) 

This is a cross-repository write (an org's authenticated webhook is able to write status/CI state onto a commit that belongs to a completely different, unrelated org's repository) and, when continuous delivery is enabled on the target stack, can translate into an unauthorized deploy — both impacts are explicitly in-scope (Critical: unauthorized deploy; High: cross-repository writes / unauthenticated mutation of stack state belonging to another org).

### Likelihood Explanation
The attacker precondition is realistic and low-privilege: they need only to be an admin of *any one* GitHub organization that has installed the Shipit GitHub App and configured its own `webhook_secret` — a normal, expected deployment configuration in multi-org Shipit installs. No Shipit account, `ApiClient` token, or access to the victim org's secret is required. They only need to know a target commit `sha` belonging to another org's tracked stack (commit SHAs for public/known repos are easily observable via GitHub).

### Recommendation
Bind the authenticated organization to the actual repository being mutated:
- In `WebhooksController`/`Handler`, after signature verification, resolve the repository from the verified organization (not from an independently-controlled `repository.owner.login`/`sha`), and reject or scope handler processing to stacks whose `Repository#owner` matches the authenticated organization.
- Specifically fix `StatusHandler#process` to scope `Commit.where(sha: params.sha)` by `stacks` (i.e., by `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`) consistent with the base `Handler#stacks` helper, and additionally verify that the repository's owner matches the organization whose secret validated the signature.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. `OrgB` has a tracked stack with continuous deployment enabled and an undeployed commit with sha `VICTIM_SHA`.
3. As an admin of `OrgA` (who only knows `OrgA`'s `webhook_secret`), POST to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "VICTIM_SHA",
  "state": "success",
  "context": "ci/fake",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/unrelated-repo" }
}
```
signed with `OrgA`'s `webhook_secret` in `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` to `OrgA`, validates the HMAC successfully against `OrgA`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: "VICTIM_SHA")`, finds the commit belonging to `OrgB`'s stack, and calls `create_status_from_github!`, creating a `success` status — potentially triggering `ContinuousDeliveryJob` and an unauthorized deploy of `OrgB`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```

**File:** app/models/shipit/status.rb (L38-44)
```ruby
    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L1-22)
```ruby
# frozen_string_literal: true

module Shipit
  class ContinuousDeliveryJob < BackgroundJob
    include BackgroundJob::Unique

    queue_as :deploys
    on_duplicate :drop

    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
  end
```

**File:** app/models/shipit/stack.rb (L211-229)
```ruby
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
