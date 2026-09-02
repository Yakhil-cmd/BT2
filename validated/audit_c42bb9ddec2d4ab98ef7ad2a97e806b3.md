### Title
Organization authenticated by webhook signature is not the same repository the webhook handlers act on, enabling cross-repository forged status/push/check_suite events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization webhook secret to validate the request signature against using one payload field (`repository.owner.login`, falling back to `organization.login`), while every event `Handler` (used to decide which `Stack`/`Repository` the event actually mutates) resolves the target repository from a *different* payload field, `repository.full_name`. Because the HMAC signature covers only the raw request body as a whole and is checked against the secret picked by `repository_owner`, an attacker who legitimately knows the webhook secret for *one* organization can self-sign an arbitrary JSON body in which `repository.owner.login` names their own org (so signature verification succeeds) but `repository.full_name` names a victim repository/stack tracked by the same Shipit instance. This breaks the binding: `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` picks the GitHub App config to check the signature with, based on the payload's owner/organization login: [1](#0-0) [2](#0-1) 

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire raw JSON payload* to the handlers unmodified. Every handler resolves the affected `Stack`/`Repository` via `Handler#repository_name`, which reads a **different** JSON key: [3](#0-2) 

For a genuine GitHub-generated webhook, `repository.owner.login` and `repository.full_name` always describe the same repository, so this discrepancy is unreachable. However, an attacker does not need to relay a real GitHub delivery — they only need to know a valid webhook secret for *some* organization onboarded to the same Shipit instance (e.g., an org they legitimately administer and configured themselves via `docs/setup.md`'s "Webhook secret" step). Using that known secret, they can HMAC-sign a **fully custom** JSON body themselves and POST it directly to `/webhooks`:
- `repository.owner.login` = "attacker-org" → makes `Shipit.github(organization: repository_owner)` load the attacker-org's `GithubApp`/secret, so `verify_webhook_signature` succeeds.
- `repository.full_name` = "victim-org/victim-repo" → makes the dispatched handler operate on the victim's `Stack`.

The `status` handler is a direct example: it materializes a `Status` record straight from the attacker-controlled payload fields (`state`, `description`, `target_url`, `context`, `created_at`) without re-verifying anything against the GitHub API, as shown by the equivalent behavior asserted in the controller test: [4](#0-3) 

Similarly `PushHandler`/`CheckSuiteHandler` resolve `stacks` purely off `repository.full_name` and enqueue sync/refresh jobs against whatever stack matches that string: [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker who controls one organization's webhook secret can forge status-check events (and push/check_suite events) targeting a completely unrelated repository/stack tracked by the same Shipit deployment. Injecting a fabricated "success" CI status on an arbitrary SHA of a victim stack can satisfy `ci.require` gating used for merges and, for stacks with `continuous_deployment: true`, can unblock/trigger automatic deploys — i.e. cross-repository writes and potentially an unauthorized deploy, matching the report's "in-scope impact" categories.

### Likelihood Explanation
This requires the attacker to legitimately possess a webhook secret for at least one organization/app installation configured on the shared Shipit instance (a realistic scenario for any multi-tenant Shipit deployment serving several orgs, since each org admin sets/knows their own webhook secret per `docs/setup.md`). No Shipit session, `ApiClient` token, or GitHub App private key is required — only the ability to sign an arbitrary raw body and POST it to the public `/webhooks` endpoint, which is unauthenticated other than the HMAC check.

### Recommendation
Verify the webhook signature using the same field that handlers use to resolve the target repository (`repository.full_name`), or, equivalently, have `verify_signature` derive the organization strictly from the resolved `Repository`/`Stack` record (looked up via `repository.full_name`) rather than trusting the separate, unauthenticated `repository.owner.login` / `organization.login` field. Additionally, handlers should confirm that `repository.owner.login` (if present) matches the owner of the repository resolved from `full_name` before acting.

### Proof of Concept
1. Attacker administers `attacker-org`, which has its own GitHub App installation and webhook secret `S` configured in Shipit (per `docs/setup.md`), and knows `S`.
2. Attacker crafts a `status` (or `push`) event JSON body where:
   - `repository.owner.login` = `attacker-org`
   - `repository.full_name` = `victim-org/victim-repo` (a stack tracked by the same Shipit instance, not owned by attacker)
   - `sha`, `state` = `success`, `context` = the CI context required by the victim stack's `shipit.yml`
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully validates the signature against `S`. [7](#0-6) 
5. `Shipit::Webhooks.for_event('status')`'s handler resolves the target stack via `repository.full_name` = `victim-org/victim-repo` and writes a forged `Status` record for that stack's commit, as demonstrated by the equivalent flow in `test/controllers/webhooks_controller_test.rb:42-59`.

Note: I was unable to open `app/models/shipit/webhooks/handlers/status_handler.rb` directly in this session (tool call failures on final iteration), so the exact status-write implementation is inferred from the corresponding controller test rather than the handler source itself; a follow-up review of that file is recommended to confirm the precise write path.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
      end
    end
  end
end
```
