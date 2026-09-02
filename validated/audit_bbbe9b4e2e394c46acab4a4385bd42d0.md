Confirmed: this is a real cross-organization spoofing vulnerability in the multi-GitHub-App configuration mode.

**The binding broken:** `organization that authenticated the webhook signature` ≠ `repository whose state is written`.

`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) selects which `GitHubApp`/webhook secret to verify the signature with, based on `repository_owner`, which is read straight from the untrusted JSON payload: [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

But every webhook handler identifies *which repository/stack to act on* using a **different** field from the same payload — `repository.full_name` — via `Handler#repository_name`: [3](#0-2) 

Nothing enforces that `repository.full_name` actually belongs to `repository.owner.login`/the organization that authenticated. In Shipit's multi-GitHub-App mode (`Shipit.github(organization:)`, documented at [4](#0-3)  and `docs/setup.md:182-209`), each organization has its own independent `webhook_secret`. A user who legitimately administers **their own** org's GitHub App/webhook (e.g. `controlled-org`, which they own) knows that org's `webhook_secret`. They can:

1. Send a POST to `/hooks` (or `/github/hooks` per `config/routes.rb`) with `X-Github-Event: push` (or `status`, `check_suite`, `membership`, etc.).
2. Set `repository.owner.login = "controlled-org"` (so `verify_signature` picks `controlled-org`'s app/secret) but `repository.full_name = "victim-org/important-repo"`.
3. Compute a valid HMAC over the raw body using `controlled-org`'s known `webhook_secret` — `verify_signature` passes.
4. `Shipit::Webhooks.for_event('push').each { |h| h.call(params) }` then runs `PushHandler`, which looks up the *victim* repo via `repository_name` (`full_name`) and calls `stack.sync_github(...)` — [5](#0-4) .

Similarly, `StatusHandler` would let the attacker forge a passing CI status (`state: "success"`) for arbitrary commit SHAs on the victim's tracked repository — [6](#0-5)  — which can unblock merges/deploys gated on CI status, since `MergeRequest` and merge-queue logic trust `Commit` statuses populated this way ( [7](#0-6) ).

This is exactly analogous to the smart-contract report's bug class: a value (`repository.owner.login`) that gates a trust decision (which secret authorizes the request) is disjoint from the value (`repository.full_name`) that determines what state gets mutated, and nothing binds the two together.

---

### Title
Cross-organization webhook spoofing via mismatched `repository.owner.login` vs `repository.full_name` in multi-GitHub-App mode - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When Shipit is configured with multiple GitHub Apps (one per organization, per `docs/setup.md`), the webhook signature is verified using the organization derived from `repository.owner.login` in the untrusted payload, but the handlers that mutate state key off a different, independently-attacker-controlled field, `repository.full_name`. An attacker who legitimately controls one organization's GitHub App webhook secret can sign a payload claiming to be from their own org while pointing `repository.full_name` at any other tracked repository, letting them push fake commits, forge CI/status events, and manipulate team membership for repositories/organizations they do not own.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the webhook secret) used to validate `X-Hub-Signature` based on `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both untrusted payload fields [8](#0-7) .

Once signature verification passes, `create` dispatches the parsed payload to all registered handlers for the event type [9](#0-8) . Every handler resolves the target repository via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a field entirely independent of `repository_owner` [3](#0-2) .

There is no check anywhere that `full_name` starts with `owner.login`, nor that the organization whose secret validated the request actually owns the repository being acted upon. In single-GitHub-App deployments this is not exploitable because there is only one secret; but Shipit explicitly documents and supports per-organization secrets for exactly this multi-tenant scenario (`docs/setup.md:182-209`, `lib/shipit.rb:170-200`).

### Impact Explanation
An attacker who administers their own GitHub organization's Shipit-integrated GitHub App (a low, self-service privilege — they only need to be an admin of *their own* org, not the victim's) can forge webhook events attributed to any other organization/repository tracked by the same Shipit instance:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for the victim's stack, potentially fabricating commits/refs that get evaluated for deploy eligibility.
- `StatusHandler` creates fabricated commit statuses (`create_status_from_github!`) for arbitrary SHAs on victim commits, which `MergeRequest::StatusChecker` and CI-gating logic rely on to permit merges/deploys.
- `MembershipHandler` can create/attach arbitrary GitHub users to arbitrary `Team`s by `github_id`, independent of the actual GitHub organization membership.

This crosses the "cross-repository writes" / "unauthorized deploy" bar for Critical impact, since it lets an attacker manipulate deploy-gating state (CI status) and stack sync state for repositories they don't control, using only credentials for an org they legitimately administer.

### Likelihood Explanation
Requires Shipit to be configured with more than one GitHub App/organization (an explicitly documented, supported configuration) and requires the attacker to be an admin of at least one such organization onboarded to the same Shipit instance — a low bar relative to compromising the victim's own webhook secret, GitHub token, or Shipit account.

### Recommendation
Bind the two identity checks together: after signature verification, reject the event unless `repository.full_name` (and/or `organization.login` for org-level events) is consistent with the organization whose secret validated the signature (e.g., `full_name.split('/').first.casecmp?(repository_owner)`), or resolve the target repository/team strictly within the scope of the authenticated organization rather than trusting `full_name`/`team.id`/`member.login` verbatim.

### Proof of Concept
1. Configure Shipit with two orgs, `controlled-org` (attacker-administered) and `victim-org` (has a tracked stack in Shipit), each with its own `webhook_secret`, per `docs/setup.md` multi-app config.
2. Attacker computes `X-Hub-Signature` over a `push` payload using `controlled-org`'s known webhook secret, with body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "controlled-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. POST to the webhooks endpoint with `X-Github-Event: push` and that signature.
4. `verify_signature` calls `Shipit.github(organization: "controlled-org")` and validates successfully (attacker knows this secret).
5. `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — despite the request never having been authorized by `victim-org`'s GitHub App.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
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
