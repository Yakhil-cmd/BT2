### Title
Webhook signature verification is keyed by the attacker-controlled `repository.owner.login`/`organization.login`, decoupled from the repository/commit actually mutated by handlers - allows cross-organization status/state forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification purely from a payload field, but the handlers that subsequently act on the very same payload identify their target (a `Repository`/`Stack`, or in the `StatusHandler` case, any `Commit` row by `sha` with no repository scoping at all) from a *different* payload field. Nothing ties the two together, so a party that legitimately possesses the webhook secret for **one** onboarded organization can forge a signed webhook payload that is verified against their own org's secret while its payload content (repository, commit sha, team/org fields) targets a **different** organization's stacks.

### Finding Description
The binding that should hold is:

`organization whose secret verified the signature == organization/repository the handler subsequently writes to`

In `verify_signature`, the organization used to pick the verification key is taken directly from the untrusted JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` loads the `GithubApp` config (and its `webhook_secret`) for whatever organization login appears in `repository.owner.login` (or `organization.login`), and the HMAC is checked against the raw body using that org's secret. If it matches, the request is allowed to reach `create`, which fans the same parsed `params` out to every registered handler: [3](#0-2) 

Handlers, however, resolve *their own* target independently of `repository_owner`. The base `Handler` uses `repository.full_name` to look up the `Repository`/`Stack`: [4](#0-3) 

and `StatusHandler` doesn't even scope by repository - it looks up **any** `Commit` in the entire database matching the attacker-supplied `sha` and stamps a GitHub status onto it: [5](#0-4) 

Because `repository.owner.login` (used for auth) and `repository.full_name` / `sha` (used for the write) are independent, attacker-controlled JSON fields inside the *same* signed body, an actor who knows the `webhook_secret` for organization A (e.g., because they administer A's own GitHub App installation in this multi-tenant Shipit deployment - multi-org support is native, see the `GithubOrganizationUnknown` rescue path and per-org `Shipit.github(organization:)` lookup) can:

1. Set `repository.owner.login` = `"org-A"` so `verify_signature` fetches and checks against A's secret, which the attacker knows and used to sign the body.
2. Set the commit `sha` (for `status`/`push`/`check_suite` events) or `repository.full_name` (for `push`/`check_suite`) to point at a **victim** organization's commit/repo that the attacker has no legitimate access to.

Because `StatusHandler#process` scopes only by `sha` with zero repository check, this lets an attacker forge a passing CI/status (`state: success`, arbitrary `context`) for any commit tracked by any stack in the instance: [6](#0-5) 

That forged status is exactly what gates deploy-safety and merge-queue decisions elsewhere in the engine (e.g. `StatusChecker`/`MergeRequest#any_status_checks_failed?`/`#reject_unless_mergeable!`), so it can cause CI to appear green on a commit that never actually passed CI, enabling an unauthorized merge or deploy of that commit on a stack the attacker doesn't control: [7](#0-6) 

`PushHandler` similarly resolves its target purely from `repository.full_name`, so the same technique can force an unrelated stack to re-sync against an attacker-chosen `expected_head_sha`: [8](#0-7) 

### Impact Explanation
This breaks the trust boundary between "the organization that authenticated the webhook" and "the repository/commit the engine writes state for." The concrete outcome - forged commit statuses feeding `MergeRequest`/CI-gating logic - can produce an unauthorized merge or deploy of a commit for a stack/organization the attacker does not administer, which matches the Critical impact bar ("unauthorized deploy, rollback or merge"). It requires no `ApiClient` token, no Shipit session, and no credentials belonging to the victim organization at all - only the webhook secret of *any* organization already onboarded to the shared Shipit instance.

### Likelihood Explanation
Exploitability depends entirely on the deployment being multi-tenant (multiple GitHub organizations configured with independent webhook secrets, a feature explicitly supported by `Shipit.github(organization:)` and the `GithubOrganizationUnknown` rescue path in `WebhooksController`). In such a deployment, any onboarded organization's own webhook secret is sufficient to attack every other onboarded organization's stacks - there is no per-target validation at all, so likelihood is high once multi-org hosting is in use. In a single-organization deployment, the two fields always agree, so the bug is latent but unreachable.

### Recommendation
Do not let handlers derive their write target from payload fields that are independent of the field used for signature verification. Either:
- Verify the signature using the same repository/organization the handler will act on (i.e., cross-check that `repository.owner.login` used for `Shipit.github(organization:)` matches the organization actually owning `repository.full_name`, and reject if they diverge), or
- Scope every handler's writes to the verified organization (e.g., have `StatusHandler` restrict `Commit.where(sha:)` to commits belonging to stacks under `repository_owner`, and have `PushHandler`/`CheckSuiteHandler` reject payloads whose `repository.full_name` owner differs from the verified `repository_owner`).

### Proof of Concept
1. Attacker legitimately administers org `org-A`'s GitHub App on a shared Shipit instance and knows `org-A`'s `webhook_secret` (`K_A`).
2. Attacker crafts a `status` event payload:
```json
{
  "sha": "<victim-commit-sha-tracked-by-a-victim-stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-A" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(K_A, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-A")`, verifies against `K_A`, succeeds.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` - matches the victim's commit (no org check) - and calls `commit.create_status_from_github!(params)`, stamping a fabricated `success` status onto a commit the attacker never had CI access to, potentially unblocking a deploy or merge for a stack belonging to a different organization entirely.

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

**File:** app/models/shipit/merge_request.rb (L155-206)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```
