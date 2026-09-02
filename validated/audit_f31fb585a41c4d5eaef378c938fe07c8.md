This confirms the vulnerability. `PushHandler#process` scopes correctly via `stacks.not_archived.where(branch:)` [1](#0-0) , using the base `Handler#stacks` method which filters by `Repository.from_github_repo_name(repository_name)` [2](#0-1) . `StatusHandler#process`, however, bypasses this scoping entirely and queries `Commit.where(sha: params.sha).each`, iterating over every commit in the entire database sharing that sha across all stacks/repositories/organizations [3](#0-2) , then calls `commit.create_status_from_github!(params)` which writes a `Status` row tied to that commit's own `stack` regardless of which repository's webhook signature was verified [4](#0-3) .

The signature verification in `WebhooksController#verify_signature` only proves the payload was signed by the organization owning the *named* `repository.owner.login` [5](#0-4) ; it says nothing about which commits/stacks may be mutated, and `StatusHandler` never re-checks `repository_name`/`stacks` before writing.

### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates every `Commit` row across the entire database that shares the posted `sha`, without filtering by the repository named in the webhook payload. Since `WebhooksController#verify_signature` only authenticates that the attacker's own organization signed the payload, an attacker owning any repository sharing a commit sha with a victim's tracked stack (e.g. via a fork sharing ancestor commits) can write arbitrary `Status` rows onto the victim's commit/stack.

### Finding Description
The broken binding: `organization_that_signed(payload) == organization_owning(Commit rows mutated)` is expected to hold, but does not.

- `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` from `payload['repository']['owner']['login']` and verifies the HMAC signature against that organization's `webhook_secret` [6](#0-5) . This only proves the attacker's own organization/app produced the signature — it never re-validates that the `sha` inside the payload actually belongs to that same organization's repository.
- `Handler#stacks` (used correctly by `PushHandler`) resolves stacks from `Repository.from_github_repo_name(repository_name)`, scoping effects to the named repository [2](#0-1)  and [1](#0-0) .
- `StatusHandler#process`, however, ignores `repository_name`/`stacks` entirely and does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) , matching commits belonging to *any* stack/organization sharing that sha.
- `create_status_from_github!` writes into `commit.statuses` (bound to the commit's own `stack_id`), triggering `enable_ci_on_stack`, `schedule_continuous_delivery`, `Hook.emit(:commit_status/:deployable_status)`, and even `stack.schedule_merges` [4](#0-3) [7](#0-6) .

Exploit flow: attacker owns `attacker/repo` and controls its `X-Github-Event: status` webhook (verified by their own org's `webhook_secret`, e.g. via `Shipit.github(organization: 'attacker')`). If a Shipit-tracked victim stack has a `Commit` row whose `sha` coincides with a commit the attacker can reference (most practically: attacker forks the victim's public repo, so ancestor commits carry identical SHAs on both repositories), the attacker POSTs `{"repository": {"owner": {"login": "attacker"}}, "sha": "<shared-sha>", "state": "success", ...}` signed with their own secret. `verify_signature` passes because the signature is valid for `attacker`'s secret. `StatusHandler` then matches and mutates the victim's `Commit` row via the unscoped `Commit.where(sha:)`, writing a forged `success` (or `failure`) `Status` for the victim's stack — potentially unblocking `deployable?`/`schedule_continuous_delivery` and misrepresenting CI state for a repository/organization the attacker never authenticated against.

No existing guard prevents this: `ExplicitParameters` only validates types/presence of `sha`/`state`, not ownership; `verify_signature` checks org-level HMAC only; `Repository`/`Stack` validations don't constrain `Commit.sha` uniqueness across stacks (the `sha` column has no global uniqueness/repo-binding constraint enforced at query time in this handler).

### Impact Explanation
An attacker who authenticates only as their own organization can write `Status` rows (CI state) attached to a victim's `Commit`/`Stack` that they do not own and never authenticated for. This can flip a victim's blocking CI checks to `success`, enabling `deployable?` to become true and triggering `ContinuousDeliveryJob`/auto-merge (`stack.schedule_merges`) — a payload for one repository mutating another's stack/commit state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any sha collision the attacker can produce, and blast radius extends to every Shipit-tracked stack/organization that happens to share a commit sha with an attacker-controlled repository (most easily achieved via GitHub forks, which share ancestor commit SHAs by design).

### Likelihood Explanation
Preconditions: the attacker must own/control a GitHub repository configured as a Shipit webhook source for some organization (their own), and there must exist a `Commit` row in a victim's stack whose `sha` matches a commit reachable by the attacker (trivially satisfied by forking any public victim repository tracked by Shipit — shared history commits keep identical SHAs). No Shipit secrets, sessions, or privileged roles are required; the attacker only needs their own valid `webhook_secret` for their own org, which they already control by configuring their own GitHub webhook. This is low-cost and repeatable per victim commit/sha.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the requesting repository's stacks, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha)).each { ... }` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring the pattern used by `PushHandler` and the base `Handler#stacks` method.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, using existing fixtures):
```ruby
test ":status from an unrelated repository mutates a foreign stack's commit" do
  # commit belongs to a different stack than "attacker/repo"
  victim_commit = shipit_commits(:cyclimse_first) # belongs to `cyclimse` stack, NOT `shipit`
  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  # verify_signature stubbed to succeed only for org 'attacker', proving the signing org != victim's org
  Shipit.stubs(:github).with(organization: 'attacker').returns(stub(verify_webhook_signature: true))

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: attacker_payload, as: :json
  end
  # Binding check: signing org ('attacker') != owning org of mutated commit (victim's org for `cyclimse`/`shipit` stack)
  assert_not_equal 'attacker', victim_commit.stack.repository.owner
end
```
This demonstrates the signed organization (`attacker`) diverging from the organization owning the mutated `Commit`/`Status`, confirming the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
