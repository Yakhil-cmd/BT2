### Title
Cross-tenant Status forgery via SHA collision in StatusHandler - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by SHA alone (`Commit.where(sha: params.sha)`) and writes a `Status` to every matching row, without ever checking that the payload's `repository.full_name` matches the `stack`/`repository` that owns each matched `Commit`. Unlike `PushHandler`, which scopes its writes through `Handler#stacks` (derived from `payload.dig('repository','full_name')`), `StatusHandler` never calls `stacks` or reads `repository.full_name` at all, so a webhook signed by one organization's `webhook_secret` can mutate `Commit`/`Status` rows belonging to a completely different organization's stack whenever the SHAs collide.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`organization_that_signed_the_webhook (verified via Shipit.github(organization: repository_owner_in_payload))` == `organization_owning_the_stack/commit_that_gets_mutated`.

Trace:
- `WebhooksController#verify_signature` [1](#0-0)  resolves `Shipit.github(organization: repository_owner)` where `repository_owner` comes from the attacker's own payload [2](#0-1) , and checks the HMAC signature against that org's `webhook_secret`. This only proves the payload was signed by the attacker's own org — it proves nothing about which `Commit` rows should be affected.
- `WebhooksController#create` dispatches to `StatusHandler.call(params)` with the full raw JSON [3](#0-2) .
- `Handler#initialize`/`.call` just parses `params` per the `ExplicitParameters` schema and calls `process` [4](#0-3) . The base class provides a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')` [5](#0-4) . `PushHandler` uses this `stacks` scope correctly [6](#0-5) .
- `StatusHandler#process`, however, bypasses `stacks` entirely and does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [7](#0-6) . No `payload.dig('repository','full_name')` read exists in this file at all.
- `Commit#create_status_from_github!` unconditionally writes a `Status` for the commit via `statuses.replicate_from_github!(stack_id, github_status)` [8](#0-7) , with no repository check.

Exploit flow: The attacker owns/controls a repository (`attacker-org/attacker-repo`) with its own valid `webhook_secret`. They craft or obtain a commit whose SHA collides with (or is identical to, e.g. via cherry-pick/copy of the same tree+metadata, or the well-known empty-tree SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`) a SHA already present as a `Commit` row in a victim stack (created from a prior legitimate push/PR sync in the victim's repo). The attacker POSTs a `status` webhook to `/webhooks`, signed with their own org's secret, with `state: 'success'` and `sha` equal to the victim's commit SHA. `verify_signature` passes because it only authenticates the attacker's own org. `StatusHandler` then matches `Commit.where(sha: ...)` across **all repositories/stacks** and writes a `success` `Status` onto the victim's commit, without ever comparing `payload['repository']['full_name']` to the victim's `commit.stack.repository`.

Existing guards do not catch this: `verify_signature` authenticates org-to-secret binding only, not org-to-commit binding; `drop_unhandled_event`/`ExplicitParameters` only validate shape; there is no `stacks`/`repository_name` check anywhere in `StatusHandler`.

### Impact Explanation
A successful `Status` write with `state: 'success'` on a victim's `Commit` can, via `Commit#status`/`deployable?`/`blocked?`/`schedule_continuous_delivery`, flip that commit into a deployable state and trigger continuous delivery (`ContinuousDeliveryJob`) or unblock manual deploys that depend on CI status — i.e., "a payload for one repository mutating another's stack/commit," and potentially causing "an unauthorized deploy" if the victim stack has continuous deployment enabled and is otherwise blocked only by this status check. This matches the Critical impact category (cross-tenant mutation / unauthorized deploy trigger). The blast radius is any tenant stack whose `Commit.sha` collides with a SHA the attacker can produce and reference from their own repo's webhook — precondition is that the victim stack already has a `Commit` row for that SHA (from a prior sync), which is a realistic scenario for widely-shared commits (e.g., empty-tree commits, vendored/cherry-picked commits, or Merkle/tree collisions across forks of the same upstream repo).

### Likelihood Explanation
The attacker needs: (1) ownership of any repository connected to Shipit with a valid `webhook_secret` for their org, (2) knowledge/production of a SHA that already exists as a `Commit` row in a target victim stack — most feasibly by forking/mirroring a repository so identical commits (same tree, parents, author/committer info, timestamps) produce identical SHA1s, which is straightforward since git SHA1s are content-addressed and reproducible without any secret. No GitHub or Shipit secrets, sessions, or elevated privileges are required beyond controlling one's own repo's webhook delivery. This is repeatable per target SHA and requires no rate-limited or novel cryptographic attack — only a SHA1 match, which is trivially achievable for repeated/copied/empty content across repos.

### Recommendation
In `StatusHandler#process`, scope the lookup to commits belonging to stacks/repositories authenticated by the incoming payload, mirroring `PushHandler`: replace the global `Commit.where(sha: params.sha)` with a lookup restricted to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently join `Commit` to `Stack`/`Repository` and filter by `payload.dig('repository', 'full_name')`), so a status update only ever touches commits belonging to the repository named in—and cryptographically authenticated for—the incoming webhook payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook from attacker org cannot mutate victim stack's commit" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = shipit_commits(:victim_stack_commit) # belongs to victim_stack, repo "shopify/shipit-engine"

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  victim_commit.reload
  assert_not_equal 'success', victim_commit.state
end
```
Binding checked on both sides: `attacker_payload.dig('repository','full_name')` ("attacker-org/attacker-repo") vs `victim_commit.stack.repository.full_name` ("shopify/shipit-engine") — before the fix these are unequal yet the write still occurs (test fails, proving the vulnerability); after adding the `stacks`-scoped lookup, the write is correctly rejected because the SHA does not belong to any stack under `attacker-org/attacker-repo`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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
