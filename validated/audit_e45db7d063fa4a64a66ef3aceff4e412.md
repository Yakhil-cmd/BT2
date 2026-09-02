### Title
Cross-repository commit-status forgery via unscoped `StatusHandler` webhook lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler`, unlike every other GitHub webhook handler in the engine, resolves the target `Commit` purely by SHA and never restricts the lookup to the repository the authenticating organization owns. This breaks the intended binding "organization whose signature authenticated the request" == "repository/stack that gets mutated," letting a webhook that is validly signed for *any* configured GitHub organization overwrite commit statuses belonging to a completely unrelated stack.

### Finding Description
`Shipit::Webhooks::Handlers::Handler` provides the standard scoping primitive used across the engine: `stacks` resolves `Repository.from_github_repo_name(repository_name)` where `repository_name` comes from `payload.dig('repository', 'full_name')`, and every handler is expected to operate only within `stacks` derived from that repository. [1](#0-0) 

`PushHandler` and `CheckSuiteHandler` correctly use this scoping — they only touch stacks belonging to the repository named in the payload: [2](#0-1) [3](#0-2) 

`StatusHandler`, however, does not call `stacks` at all. It queries `Commit` globally by SHA and writes the status directly: [4](#0-3) 

The only gate before a handler runs is `WebhooksController#verify_signature`, which selects the GitHub App/secret to validate against using `repository_owner`, itself read straight out of the unauthenticated payload (`params.dig('repository', 'owner', 'login')`): [5](#0-4) [6](#0-5) 

This verification only proves that the request was signed with *some* configured organization's `webhook_secret` — it says nothing about which `repository.full_name`/commit SHA the payload body actually references. Because `StatusHandler` never re-checks that the SHA it is about to update belongs to a stack under that same organization, a validly-signed `status` event for organization A can be crafted with an arbitrary `sha` value that happens to belong to a commit tracked under organization B's stack, and the handler will happily call `commit.create_status_from_github!(params)` on it.

The analog to the reported bug class is direct: in the Solidity report, a single unvalidated input (`msg.value`) is reused across loop iterations without being tied to the correct per-iteration state, corrupting `totalFeeCollectedETH`. Here, a single unvalidated input (`payload['sha']`) is used to look up and mutate state (`Commit`) without being tied to the organization/repository binding that the surrounding authentication step is supposed to enforce — the authenticated organization and the repository actually written are two different, unchecked things.

### Impact Explanation
Commit statuses feed into deploy/merge gating logic (`Status::Group`, `Commit#create_status_from_github!`, `MergeRequest`, `DeploySpec` required statuses). An attacker who can get any organization onboarded to the Shipit instance to send them a legitimately-signed `status` webhook (or who controls/administers one low-value organization configured in the multi-tenant `Shipit.github` setup) can forge a "success" status against a commit SHA belonging to a different, higher-value organization's stack — provided that SHA is known (commit SHAs are frequently public via GitHub UI/PRs). This can satisfy required-status gating used to unblock an unauthorized merge or deploy on a stack the attacker has no legitimate relationship to, which matches the "unauthorized deploy, rollback or merge" High-impact criterion.

### Likelihood Explanation
Exploitability depends only on: (1) the attacker being able to produce a validly-signed webhook for *some* organization known to the Shipit instance (an org they administer, or one with no `webhook_secret` configured, where `verify_webhook_signature` returns `true` unconditionally), and (2) knowledge of a target commit SHA in a victim stack, which is typically public. No repository write access, API token, or session is required — this is a pure unprivileged, cross-tenant confusion bug reachable through the public `/webhooks` endpoint.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup the same way `PushHandler`/`CheckSuiteHandler` do — restrict the query to commits belonging to `stacks` (i.e., to the repository named in `payload['repository']['full_name']`), not a bare global `Commit.where(sha: ...)`. More generally, add an assertion in `Handler` (or in `WebhooksController`) that the organization used to verify the webhook signature matches the owner of `payload['repository']['full_name']` before any handler executes, closing the gap for every current and future handler rather than just this one.

### Proof of Concept
1. Configure/identify an organization `attacker-org` in the multi-tenant Shipit config (either one the attacker administers, or one without a `webhook_secret` set, for which `GithubApp#verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb` line 77).
2. Send `POST /webhooks` with header `X-Github-Event: status`, a valid (or bypassed) signature for `attacker-org`, and a JSON body:
```json
{
  "repository": {"full_name": "attacker-org/irrelevant-repo", "owner": {"login": "attacker-org"}},
  "sha": "<known SHA of victim-org/victim-repo commit>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `WebhooksController#verify_signature` validates against `attacker-org`'s secret (or is bypassed) and succeeds.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, updating the status on the victim commit regardless of the fact that the request was authenticated as `attacker-org`, not the victim organization that owns that commit's stack.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
