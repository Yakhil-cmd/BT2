### Title
Webhook signature verified against `repository.owner.login`, but the `status` event acts globally on `Commit.sha` with no repository/organization scoping - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` computes the HMAC over the raw payload using the GitHub App secret selected by `repository_owner`, a value read straight out of the attacker-supplied JSON body (`params.dig('repository','owner','login')`). The handler that actually mutates state for a `status` event, `Shipit::Webhooks::Handlers::StatusHandler`, never checks `repository` at all - it looks up commits with `Commit.where(sha: params.sha)` across the entire installation and calls `commit.create_status_from_github!`. In a multi-organization Shipit deployment (explicitly documented and supported via `config/secrets.yml`'s per-organization `github:` section), the "organization that authenticated" (used to pick the HMAC secret) is never bound to "the repository/commit that is written." An attacker who legitimately administers one onboarded organization's GitHub App - and therefore knows that org's `webhook_secret` - can sign an arbitrary payload with `repository.owner.login` set to their own org, but with a `sha` belonging to a commit in a completely different organization's stack, and inject a fabricated CI status (`state: "success"`, arbitrary `context`) for that foreign commit.

### Finding Description
- Signature verification: `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(...)` are computed from `repository_owner`, itself parsed from the JSON body (`params.dig('repository','owner','login')`), at `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
- Event dispatch happens on the raw parsed body, calling every registered handler for the event with the full payload: `app/controllers/shipit/webhooks_controller.rb:10-15`.
- `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:6-24`) only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` as parameters - it never requires or validates a `repository` field, unlike other handlers (e.g. `PushHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`s) that route through `Handler#stacks`/`#repository_name`, which derive scope from `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).
- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` - a global, cross-tenant lookup with no join to `Repository`/`Stack` ownership at all.
- `Commit#create_status_from_github!` → `#add_status` (`app/models/shipit/commit.rb:165-169,366-386`) creates a `Status`, recomputes `Commit#status`, and if the state transitions to `pending`/`success` calls `stack.schedule_merges` - directly feeding the merge queue (`ProcessMergeRequestsJob`) and continuous-delivery scheduling (`Commit#schedule_continuous_delivery`, `app/models/shipit/commit.rb:281-287`) which can trigger an actual deploy via `Stack#trigger_continuous_delivery`.
- The result is a binding break precisely of the class the rules call out: "an organization that authenticated versus the repository that is written." The org used to select/verify the HMAC key (`repository.owner.login`) is never checked against the repository/stack that the handler actually mutates (derived independently from `sha`, with `StatusHandler` not even consulting `repository.full_name`).

### Impact Explanation
An attacker who is a legitimate, unprivileged operator of one tenant organization onboarded to a multi-org Shipit instance can forge CI status for any commit in any other tenant's stack, without ever obtaining that other organization's webhook secret, GitHub token, or Shipit session/API token. Faking a `success` status on a `required_statuses` context can unblock `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) and `Commit#blocked?`, causing `stack.schedule_merges` and continuous-delivery/merge-queue logic to proceed and merge or deploy a commit under an organization the attacker doesn't own — an unauthorized deploy/merge (Critical per the rubric) driven purely by a cross-tenant credential/scope confusion.

### Likelihood Explanation
Requires: (1) a Shipit installation configured for multiple GitHub organizations (explicitly documented as a supported setup in `docs/setup.md`), and (2) the attacker controlling one of the onboarded orgs' GitHub App and therefore knowing its `webhook_secret` (which the org admin who created that App chooses themselves and legitimately possesses). No breach of another org's secrets, no GitHub App private key, no Shipit session or `ApiClient` token is needed — only knowledge of the sha of a target commit in the victim stack (visible in Shipit's public/team UI or in GitHub PR pages) and a single crafted HTTP POST to `/webhooks`. This is a realistic, unprivileged, credential-legitimate attacker per the scope rules.

### Recommendation
Bind the authenticated organization to the acted-upon resource: `StatusHandler` (and any handler that doesn't already scope through `Handler#stacks`) must require and validate `repository.full_name`/`repository.owner.login`, resolve the target `Stack`/`Repository` from it, and only touch commits (`Commit.where(sha: ..., stack: stack)`) belonging to that repository — matching the same organization that was used to verify the signature. More generally, `WebhooksController` should pass down the verified `repository_owner`/organization to every handler and have `Handler` reject any payload whose `repository.owner.login`/`full_name` do not match the organization whose secret validated the signature.

### Proof of Concept
1. Shipit configured with two tenant orgs, `orgA` (attacker-controlled, webhook secret known to attacker) and `orgB` (victim, has a stack with `required_statuses` including `ci/circle`).
2. Attacker crafts JSON body:
```json
{
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/some-repo"},
  "sha": "<victim commit sha in orgB's stack>",
  "state": "success",
  "context": "ci/circle",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` succeeds because `repository_owner == "orgA"` and the signature matches orgA's secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — finds the commit belonging to orgB's stack regardless of the `repository` field — and calls `commit.create_status_from_github!(params)`, injecting a fake `success` status and potentially triggering `stack.schedule_merges` / continuous delivery for orgB's stack (`app/models/shipit/commit.rb:165-169,281-287,366-386`). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
    end
```
