### Title
`StatusHandler` forges CI statuses on any repository's commits using another organization's authenticated webhook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an inbound GitHub webhook by looking up the GitHub App/organization keyed off `params.dig('repository', 'owner', 'login')` from the payload, then checking the `X-Hub-Signature` HMAC against that organization's `webhook_secret`. This proves only that the payload was legitimately signed by *some* organization that has the Shipit GitHub App installed. However, `Shipit::Webhooks::Handlers::StatusHandler#process` does not scope its side effect to that authenticated repository/organization at all.

### Finding Description
The equality the engine implicitly relies on is: `organization that signed the webhook == repository/stack whose data is mutated`. `WebhooksController#verify_signature` resolves the signing organization from `repository_owner` in the payload [1](#0-0) , and only that organization's secret is checked against the signature over the raw payload [2](#0-1) .

Once verified, `StatusHandler#process` looks up commits purely by `sha`, globally across the entire `commits` table, with no join or filter on `repository`/`stack`/organization: [3](#0-2) 

Compare this to `PushHandler`, which correctly scopes to `stacks` derived from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`Handler#repository_name` [4](#0-3) [5](#0-4) . `StatusHandler` inherits from the same `Handler` base but never uses `stacks`/`repository_name` to constrain the `Commit` lookup [6](#0-5) .

Because Shipit is multi-tenant (any organization/repository owner that installs the Shipit GitHub App gets its own `webhook_secret` and can send validly-signed webhooks for its own repository), an attacker who controls a repository/organization onboarded onto the same Shipit instance can send a legitimately-signed `status` event for their own repo, but set `sha` to a commit SHA belonging to a completely different tracked stack/repository. Because SHAs are effectively globally unique, this lets the attacker's own (correctly authenticated) webhook write a forged commit status (e.g., `state: "success"`) onto an arbitrary commit belonging to another tenant's stack, via `Commit#create_status_from_github!` → `Commit#add_status` [7](#0-6) .

This breaks the binding "organization that authenticated versus the repository that is written" described in the report's bug class analog: the signature only proves the request came from organization A, but the handler writes into organization B's data because there is no repository/stack scoping analogous to `PushHandler`.

### Impact Explanation
`Commit#deployable?` gates whether a commit can be auto-deployed under continuous delivery: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [8](#0-7) , and `status` is derived directly from the `statuses` written by `StatusHandler` [9](#0-8) . Forging a `success` status on a victim stack's commit, combined with `Commit#schedule_continuous_delivery`, can trigger `ContinuousDeliveryJob` for a stack the attacker has no access to [10](#0-9) , i.e. an unauthorized deploy of another tenant's stack/commit that never actually passed CI — this maps to the Critical "unauthorized deploy" impact category.

### Likelihood Explanation
This requires only that the attacker control any repository/organization onboarded to the shared Shipit instance (a low, self-service bar — install the GitHub App on their own org/repo, which is the normal onboarding flow, not a privileged Shipit account, `ApiClient` token, or GitHub App private key) and know/guess a target commit SHA (SHAs are frequently public via GitHub UI, PRs, or Shipit's own commit pages). No repository write access, TLS interception, or session compromise is needed.

### Recommendation
Scope `StatusHandler#process` to the repository indicated by the (already signature-verified) webhook payload, consistent with `PushHandler`, e.g. filter through `stacks` (derived from `payload.dig('repository', 'full_name')`) before matching by `sha`, rather than querying `Commit` unscoped by `sha` alone.

### Proof of Concept
1. Attacker creates/owns GitHub org `attacker-org` and repo `attacker-org/repo`, installs the Shipit GitHub App on it (self-service, normal onboarding), and obtains its `webhook_secret`.
2. Attacker identifies a commit SHA `deadbeef...` belonging to a victim stack `victim-org/victim-repo` tracked by the same Shipit instance (visible via GitHub or Shipit's public commit views).
3. Attacker sends a `status` event to `/webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with `attacker-org`'s webhook secret, and body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "repository": {"full_name": "attacker-org/repo", "owner": {"login": "attacker-org"}}
}
```
4. `WebhooksController#verify_signature` validates the signature against `attacker-org`'s secret and passes [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the victim's commit (owned by `victim-org/victim-repo`), and writes a forged `success` status via `create_status_from_github!` [3](#0-2) .
6. If `victim-org/victim-repo`'s stack has continuous deployment enabled, `schedule_continuous_delivery` fires and the forged-CI-green commit is auto-deployed [10](#0-9) .

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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```
