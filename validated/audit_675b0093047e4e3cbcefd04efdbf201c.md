### Title
`StatusHandler#process` updates commits across all stacks by SHA alone, letting one repository's signed webhook fire `Hook.emit` for another repository's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up `Commit.where(sha: params.sha)` with no scoping to the repository that authenticated the webhook, then calls `commit.create_status_from_github!` for every match, which ultimately runs `Commit#add_status` and fires `Hook.emit(:commit_status, stack, ...)` / `Hook.emit(:deployable_status, stack, ...)` using `commit.stack` [1](#0-0) [2](#0-1) . Because git SHAs are identical across a repository and any of its forks, a GitHub `status` webhook that is legitimately and correctly signed for the attacker's own fork/org can update and fire hooks for a completely unrelated victim stack that happens to track the same commit.

### Finding Description
The broken binding, stated explicitly: the code assumes
`stack (passed to Hook.emit)` == `stack of the organization that authenticated the webhook (repository_owner used in verify_signature)`.

Tracing the path shows this equality does not hold:

1. `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)` [3](#0-2) . This only proves the payload was signed by *some* registered org's secret — the org named in the payload's own `repository.owner.login`, which can be the attacker's own org/fork.
2. `StatusHandler#process` never consults `payload['repository']` at all. It queries `Commit.where(sha: params.sha)` globally, across every stack in the installation, and calls `commit.create_status_from_github!(params)` for each match [1](#0-0) . Note the base `Handler` class already provides a `stacks` helper that scopes by `payload.dig('repository', 'full_name')` [4](#0-3) , but `StatusHandler` does not use it.
3. `create_status_from_github!` → `add_status` uses `stack` (delegated to `commit.stack`, i.e., whichever stack owns the matched `Commit` row) to build the `Hook.emit` payload: `Hook.emit(:commit_status, stack, ...)` and `Hook.emit(:deployable_status, stack, ...)` [2](#0-1) .

Root cause: git SHAs are content-addressed and identical across a repository and any fork of it. If a victim's Shipit stack tracks `victim/app`, and the attacker forks it to `attacker/app` (an action explicitly within the stated attacker capabilities), every commit inherited from the upstream history has the *same SHA* in both repos. GitHub will deliver a legitimately-signed `status` webhook for the attacker's fork (e.g. via the GitHub Statuses API on a commit in `attacker/app`) using the attacker's own org's real webhook secret. `verify_signature` passes because the signature is valid for `attacker`'s org. But `StatusHandler#process` then matches the shared SHA against `victim/app`'s `Commit` row too, and fires `Hook.emit` with `stack == victim's stack`, driving the victim's configured Slack/webhook integrations and triggering `stack.schedule_merges` for the victim off attacker-controlled `state`/`context`/`description` values.

None of the existing guards prevent this: `verify_signature` authenticates the org named in the payload, not which stacks may be mutated; `drop_unhandled_event` only checks event type; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not ownership; and there is no `stack`/repository scoping anywhere in `StatusHandler`.

### Impact Explanation
The attacker can cause arbitrary configured `Hook`s (Slack notifications, generic webhooks, custom integrations) on a victim's stack to fire with attacker-chosen `state`, `description`, `context`, and `target_url`, and can also trigger `stack.schedule_merges` (which invokes `ProcessMergeRequestsJob`) on the victim's stack when the forged status is `pending` or `success` [5](#0-4) . This is a payload for one repository (the attacker's fork) mutating another repository's stack (the victim's), matching the Critical impact category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any victim stack whose tracked history overlaps with a repository/fork the attacker controls, and the blast radius spans every stack in the multi-tenant Shipit installation that shares commit ancestry with an attacker-controlled repository.

### Likelihood Explanation
Preconditions: (1) the victim stack has outbound `Hook`s configured that trust `commit_status`/`deployable_status` payloads (a common, documented Shipit feature); (2) the attacker's own repository/org must be a recognized org already configured in the same Shipit installation with a valid webhook integration (so that `Shipit.github(organization: repository_owner)` does not raise `GithubOrganizationUnknown`, and legitimate GitHub-delivered signatures verify) — this is realistic in any Shipit deployment used by multiple teams/orgs within the same GitHub Enterprise or organization, or wherever an attacker can register/onboard their own fork as a Stack. Given that, the attack cost is low: fork the victim's repo, set a custom commit status via GitHub's API on any inherited commit, and let GitHub deliver the legitimately-signed webhook. No secrets need to be extracted; the attacker only leverages the SHA collision inherent to forking, which is trivially repeatable for every shared commit.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed handler) to only the commits belonging to the repository that authenticated the webhook, e.g. use the existing `stacks` helper (`Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks`) to filter: `Commit.where(sha: params.sha, stack: stacks)`, rather than querying `Commit` globally by `sha` alone.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or equivalent):
```ruby
test "status webhook for one repository does not fire hooks for another stack sharing the same SHA" do
  victim_stack = shipit_stacks(:shipit)          # e.g. repo "shopify/shipit-engine"
  attacker_stack = Stack.create!(repository: Repository.create!(owner: 'attacker', name: 'fork'))

  shared_sha = victim_stack.commits.first.sha
  # Simulate the shared history: the attacker's fork contains a Commit row with the same sha
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/fork', 'owner' => { 'login' => 'attacker' } }
  }

  Hook.expects(:emit).with(:commit_status, victim_stack, anything).never
  Hook.expects(:emit).with(:deployable_status, victim_stack, anything).never
  Hook.expects(:emit).with(anything, attacker_stack, anything).at_least(0)

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)
end
```
Assert on both sides of the binding: `attacker's authenticated org == "attacker"` (from `verify_signature`) vs `stack passed to Hook.emit == victim_stack` (observed) — the test proves these diverge, confirming the cross-tenant firing.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
