### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes an incoming GitHub `status` webhook payload to *any* `Commit` row in the entire Shipit database that matches the given `sha`, without ever checking that the payload's `repository.full_name` matches the stack/repository that owns that commit. Every other handler in the same directory resolves the target through `stacks` (which is scoped by `Repository.from_github_repo_name(repository_name)`), but `StatusHandler` bypasses that scoping entirely, allowing a webhook from an attacker-controlled repository to overwrite the CI status of a commit belonging to a completely unrelated repository/stack.

### Finding Description
The binding that should hold is: `commit.statuses.last.state == GitHub's true CI state for commit.sha as reported by commit.stack's repository`. This binding is broken at write time, not merely by staleness/timing as framed in the question.

Code path:
- `Shipit::WebhooksController#create` dispatches the parsed JSON `params` to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which only validates that the payload was signed by the GitHub App belonging to `repository_owner` (`params.dig('repository','owner','login')`) — i.e. it proves *which org/repo* sent the webhook, not that the `sha` inside the payload belongs to that repo [1](#0-0) .
- `Shipit::Webhooks::Handlers::Handler` provides a `stacks` helper explicitly scoped to the sending repository via `Repository.from_github_repo_name(repository_name)` [2](#0-1) .
- `StatusHandler#process`, however, ignores `stacks`/`repository_name` completely and instead does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .
- `create_status_from_github!` unconditionally persists the state via `add_status`/`statuses.replicate_from_github!`, which then feeds `Commit#status`, `#success?`, `#deployable?` [4](#0-3) [5](#0-4) .

Exploit flow: an attacker who owns/controls a repository whose webhooks reach the shared Shipit GitHub App (satisfying the stated precondition of being able to "emit webhooks from a repository they own") sets a commit status via GitHub's Status API using the **victim's** commit SHA as the target (GitHub's Statuses API does not require the SHA to belong to an ancestor commit already present in the attacker's repo history). GitHub delivers a `status` webhook, signed for the attacker's own org, containing `sha = <victim sha>`, `state = success`, `repository.full_name = attacker/repo`. `verify_signature` passes (it is a legitimate signature for the attacker's own org). `StatusHandler#process` then finds the victim's `Commit` purely by `sha` — with no cross-check against `repository.full_name` — and writes a fabricated "success" status onto it.

This is why the question's framing about "no repeating refresh" understates the real bug: even a repeating refresh would not fully mitigate this, because `RefreshStatusesJob` only re-syncs statuses that GitHub reports for the commit's *own* repo/sha, and the forged status can simply be re-submitted by the attacker again at will (repeatable, not merely a one-time race). The core defect is that the write path has no repository binding check at all, so the "true" state is never enforced.

### Impact Explanation
An attacker who controls (or can push webhooks from) any repository serviced by a shared Shipit/GitHub App installation can inject a `success` (or any) CI status onto a commit belonging to an entirely different repository/stack that they do not control, directly influencing `Commit#deployable?` and `schedule_continuous_delivery`, which can trigger an unauthorized deploy of the victim stack, or unblock a merge that depends on `all_status_checks_passed?`/`blocking_statuses`. This is a "payload for one repository mutating another's stack/commit," matching the Critical impact category, and it is repeatable against any commit SHA the attacker can discover (e.g. via the victim's public GitHub PR/commit history) at no cost beyond one webhook delivery per forgery.

### Likelihood Explanation
Preconditions: the attacker needs a repository that is wired to send webhooks that pass `verify_signature` — i.e., a repository under a GitHub App/organization installation Shipit already trusts (this capability is explicitly granted in the attacker model provided). No Shipit session, API token, or maintainer status is required, and no interaction with the victim stack's own repository or secrets is needed. The forged `sha` need not be a real commit in the attacker's own repo. This makes the attack cheap, fully attacker-controlled, and repeatable at will (not a narrow timing race).

### Recommendation
Scope `StatusHandler#process` (and any other handler with similar direct `Commit`/`sha` lookups) to the sending repository, mirroring the base `Handler#stacks` pattern, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a webhook can only write statuses for commits belonging to the repository that actually authenticated the webhook.

### Proof of Concept
Under `test/models/webhooks/handlers/status_handler_test.rb` (or existing `status_handler_test.rb`):
1. Create two stacks/repositories, `victim/repo` and `attacker/repo`, each with a `Commit` sharing the same `sha` (simulate collision by directly inserting two `Commit` rows with an identical `sha` under different `stack_id`s, since the handler has no repo scoping to prevent this in the first place).
2. Build a `status` webhook payload with `repository.full_name = "attacker/repo"`, `sha = <shared sha>`, `state = "success"`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
4. Assert: `victim_commit.reload.status.state == "success"` even though the payload's `repository.full_name` was `attacker/repo`, proving `commit.statuses.last.state` no longer reflects `victim/repo`'s true CI state — i.e., the equality `commit.status.state == GitHub_state_for(commit.stack.repository, commit.sha)` is broken.
5. Assert `victim_commit.deployable?` reflects the forged state, demonstrating downstream impact on deploy gating.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
