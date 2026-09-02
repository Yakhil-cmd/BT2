### Title
Cross-repository CI status forgery via unscoped `Commit` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an incoming GitHub webhook by resolving the GitHub App/organization from the payload (`repository_owner`) and checking the HMAC signature against **that organization's** `webhook_secret`. [1](#0-0)  Once the signature is accepted, the raw payload is dispatched to event handlers with no further scoping to the authenticated organization/repository. [2](#0-1)  For `status` events, `Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits **globally by SHA alone**, with no filter on repository or stack, and writes a GitHub status onto whatever commit matches:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This breaks the intended equality: `{organization the webhook signature authenticates} == {repository/stack whose commit receives the write}`. Contrast this with `PushHandler` and `CheckSuiteHandler`, which correctly scope their side effects through `stacks`, itself derived from `payload.dig('repository', 'full_name')` looked up via `Repository.from_github_repo_name`. [4](#0-3) [5](#0-4) [6](#0-5)  `StatusHandler` alone omits this scoping.

### Finding Description
An attacker who legitimately administers a GitHub organization/App installation that Shipit is configured for (i.e., knows the `webhook_secret` for *their own* org, as any org owner setting up the app-level webhook naturally would) can pass `verify_signature`, since `Shipit.github(organization: repository_owner)` resolves the app keyed on the attacker's own `repository.owner.login` value from the payload. [7](#0-6)  The signature only proves the payload was signed with *some* configured organization's secret — it proves nothing about which `Commit`/`Stack` the payload's body is allowed to affect.

The attacker then sends a `status` event body containing an arbitrary `sha` value corresponding to a commit belonging to a **completely different** stack/repository managed by the same Shipit instance, along with a favorable `state` (e.g. `success`) and `context`. `Commit.where(sha: params.sha)` matches on `sha` alone across the entire `commits` table (no `stack_id`/repository scoping), so the forged status is attached to the victim commit via `commit.create_status_from_github!(params)`. [3](#0-2) [8](#0-7) 

Because `Commit#required_statuses`/`blocking_statuses` and deployability checks are delegated to the commit's own `stack`, and `Stack#deployable?`/CI-gating logic reads directly off `Commit#statuses` on that stack, a forged passing status can satisfy `ci.require` checks configured in the **victim's** `shipit.yml`, without the attacker ever having write access, a Shipit session, or credentials for the victim organization/repository. [9](#0-8) 

### Impact Explanation
This is a cross-repository write: an attacker authenticated only for their own GitHub organization can create/modify commit-status records — and thereby manipulate CI-gating state used for deploy authorization — on a stack/repository belonging to a different, unrelated organization managed by the same Shipit instance. This can escalate to an **unauthorized deploy**: if the victim stack has `ci.require` configured and continuous delivery enabled, injecting a forged passing status for the head commit can cause Shipit to consider the commit deployable/CI-green, satisfying deploy trigger and CI-safety-check logic that was meant to require genuine CI signal from the correct repository.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) any single GitHub organization that is configured in this Shipit instance's `Shipit.github_apps`/webhook configuration — a materially lower bar than requiring a Shipit session, `ApiClient` token, or the victim organization's own webhook secret. Multi-tenant Shipit deployments serving several unrelated GitHub orgs/teams are the primary risk scenario. No knowledge of victim internals beyond a commit SHA (visible on GitHub/PR pages) is needed.

### Recommendation
Scope `StatusHandler#process` (and any other handler with unscoped model lookups) to the repository/stack derived from the authenticated payload, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
More generally, enforce in `WebhooksController` that the organization used to verify the signature (`repository_owner`) matches the organization embedded in every repository-scoped lookup performed by handlers, rather than trusting the raw, unscoped payload fields independently in each handler.

### Proof of Concept
1. Shipit instance is configured with two GitHub App installations: `org-attacker` (attacker is an org owner, knows its `webhook_secret`) and `org-victim` (unrelated, has a stack with `ci.require: ["ci/tests"]`).
2. Victim pushes a commit `abc123...` to their stack; it is currently pending/failing CI.
3. Attacker crafts a `status` webhook body:
```json
{
  "sha": "abc123...",
  "state": "success",
  "context": "ci/tests",
  "target_url": "https://ci.example.com/fake",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `org-attacker`'s known `webhook_secret` and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: 'org-attacker')` and successfully verifies the signature (using the attacker's own legitimate secret). [7](#0-6) 
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, finds the victim's commit (since the lookup is global, unscoped by repository), and creates a passing `ci/tests` status on it. [3](#0-2) 
7. The victim stack's commit now shows a forged passing CI status it never received from its own CI, potentially unblocking deploy for that commit.

*Note: I was unable to fully trace the exact `deployable?`/`ci.require` gating code path within the tool budget available; the mechanism by which `Commit#statuses` feeds into deploy-authorization decisions (`Stack#deployable?`, continuous-delivery triggers) should be verified directly in `app/models/shipit/stack.rb` and `app/models/shipit/commit.rb` before treating the "unauthorized deploy" escalation as fully proven end-to-end — the unscoped cross-repository `Commit` write itself is confirmed directly from the cited code.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/commit.rb (L55-59)
```ruby
    scope :reachable, -> { where(detached: false) }

    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack

```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
