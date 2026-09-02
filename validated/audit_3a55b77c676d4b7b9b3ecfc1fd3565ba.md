### Title
Cross-repository `Status` write via SHA collision in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up `Commit` rows by `sha` alone, globally across all repositories, and never validates that the SHA belongs to the repository named in the incoming webhook payload. Because git commit SHAs are attacker-influenceable content hashes (not secrets), an attacker who controls repository R2 can craft a commit whose SHA collides with a commit already recorded for victim repository R1 (e.g., the well-known empty-tree/empty-commit SHA, or any commit with attacker-controlled tree/parents/author/committer/timestamps/message reproduced to match), and push it to R2 to trigger a legitimately-signed `status` webhook for R2 that nonetheless writes a `Status` onto R1's `Commit` row.

### Finding Description
Broken binding: `repository_named_in_payload(webhook.payload['repository']['full_name'])` should equal `repository_owning_commit_mutated(Commit#stack#repository)` for every `Commit` row touched by the handler — but it does not.

Code path:
- `Shipit::WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers, after only checking `verify_signature`, which resolves the GitHub App config via `Shipit.github(organization: repository_owner)` and HMAC-validates the payload against that organization/app's `webhook_secret` [1](#0-0) . This only proves "someone holding R2's app webhook secret sent this payload" — it says nothing about which `Commit`/`Stack` rows may be touched.
- `StatusHandler#process` then runs:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
This query has no `stack_id`/repository filter at all, unlike the base `Handler` class which offers a `stacks`/`repository_name` helper scoped via `Repository.from_github_repo_name(repository_name)` [3](#0-2)  — `StatusHandler` simply never calls it.
- `Commit#sha` has no uniqueness validation enforced across the whole table (only meaningful within a stack in practice), and `Commit#create_status_from_github!` unconditionally creates a `Status` record and triggers hooks/side effects (`add_status`, `Hook.emit(:commit_status, ...)`, `stack.schedule_merges`) [4](#0-3) [5](#0-4) .

Exploit flow:
1. Attacker owns repository R2 with a Shipit-connected GitHub App (their own `webhook_secret`, no privilege over R1).
2. Attacker crafts/pushes a commit to R2 whose SHA is identical to a SHA already present as a `Commit` row under victim `Stack` for repository R1 (trivial for the fixed empty-tree/empty-commit SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`/`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`-style objects, or any commit whose full byte content — tree, parents, author, committer, timestamps, message — the attacker reproduces).
3. GitHub sends a `status` webhook to Shipit for R2, HMAC-signed with R2's own webhook secret, with `sha: SHA_X`, `repository.full_name: 'attacker/R2'`.
4. `verify_signature` passes (correctly, for R2's app).
5. `StatusHandler#process` runs `Commit.where(sha: SHA_X)`, matches R1's commit row too, and writes/updates a `Status` on it, feeding attacker-controlled `state`/`description`/`target_url`/`context` into R1's commit status — potentially flipping victim commit status to "success" and unblocking `deployable?`/`schedule_continuous_delivery` for R1.

Existing guards do not stop this: `verify_signature` authenticates the sender's app/org, not the target rows; `ExplicitParameters` schema only validates payload shape, not repository ownership; `drop_unhandled_event` only filters by event type; there is no `stacks`/`repository_name` scoping in `StatusHandler`.

### Impact Explanation
An attacker who controls an unrelated repository (R2) can cause an unauthorized write of a `Status` record on a victim stack's commit (R1) without any relationship between the two repositories being verified — this is a cross-tenant record mutation triggered by a payload authenticated for one repository but applied to another's commit. Because `Status` state feeds `Commit#status`/`deployable?` and can trigger `stack.schedule_merges`/continuous delivery scheduling, this can influence whether R1's commit is treated as deployable, i.e., an unauthorized effect on deploy readiness for a tenant the attacker does not control. This matches "a payload for one repository mutating another's stack/commit" — Critical.

### Likelihood Explanation
Preconditions: attacker needs any GitHub App-backed repository with Shipit installed and its own valid webhook secret (something any external repo owner using this Shipit instance's GitHub App plausibly has), and needs a SHA collision with a commit in a targeted victim's `Commit` table. Full SHA-1 preimage collision against an arbitrary chosen victim SHA is currently computationally infeasible, but the well-known deterministic "empty commit"/well-known SHAs, or any scenario where the same commit is legitimately pushed/mirrored to multiple repos (e.g., forks sharing history, vendored/synced commits, cherry-picks preserving identical content and metadata) will produce identical SHAs across repositories that Shipit tracks as separate stacks. This is a real, repeatable technique for repos with shared or mirrored history and does not require any secret beyond the attacker's own app credentials.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository named in the payload, mirroring `Handler#stacks`, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or more efficiently, join through `Stack`/`Repository` to filter `Commit.where(sha: params.sha)` by `stack: { repository: repository_from_payload }`. Add a uniqueness scoping consideration too, ensuring cross-repository `sha` collisions cannot cause cross-tenant writes even incidentally.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, illustrative — actual file is out of scope per rules but described for reference):
1. Create two `Repository`/`Stack` fixtures, R1 (victim) and R2 (attacker's), each with a distinct GitHub App config/`webhook_secret`.
2. Create a `Commit` under R1's stack with `sha: SHA_X` and no `Status` rows yet. Assert `commit.statuses.count == 0`.
3. POST to `/webhooks` with `X-Github-Event: status` and body `{sha: SHA_X, state: 'success', repository: {full_name: 'attacker/R2', owner: {login: 'attacker'}}}`, signed with R2's `webhook_secret` via `X-Hub-Signature`.
4. Assert response is `200 OK` (signature accepted for R2).
5. Reload R1's commit and assert `commit.statuses.count == 1` and `commit.status.state == 'success'`, proving a payload authenticated for R2 mutated R1's commit — i.e., `repository_named_in_payload('attacker/R2') != repository_owning_commit_mutated('victim/R1')` yet the write succeeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
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
