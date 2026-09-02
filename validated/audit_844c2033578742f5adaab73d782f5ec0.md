### Title
`StatusHandler#process` mutates commit statuses across all stacks sharing a `sha`, with no repository/stack scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `sha` alone (`Commit.where(sha: params.sha)`) and calls `create_status_from_github!` on every match, with no filter tying the mutation to the repository that authenticated the incoming webhook. Unlike the base `Handler` class, which exposes a `stacks` helper scoped via `Repository.from_github_repo_name(repository_name)`, `StatusHandler` bypasses that scoping entirely.

### Finding Description
Binding claimed: `distinct stack_id values mutated per status webhook == 1` (the legitimate stack tied to the webhook's authenticated repository). Actual code: [1](#0-0) 

`process` iterates `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — an unconditional `.each` with no `.first`, no `stack_id` filter, and no reference to `payload.dig('repository', 'full_name')`. Contrast with the base `Handler` class, which defines a repository-scoped `stacks` method intended for this exact purpose but which `StatusHandler` never calls: [2](#0-1) 

`Commit#create_status_from_github!` writes a new `Status` row and triggers hooks/side effects (`schedule_merges`, `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`) per matched commit, regardless of which stack it belongs to: [3](#0-2) [4](#0-3) 

`WebhooksController#verify_signature` only checks that the HMAC signature is valid for the organization derived from `repository.owner.login` in the payload — it authenticates *that the request came from GitHub for that organization's app installation*, it does **not** scope the subsequent database write to that repository/stack: [5](#0-4) 

Because `Commit` rows are stored per `stack_id` but looked up globally by `sha` with no repository predicate, any `Commit` row in *any* stack whose `sha` matches the incoming payload's `sha` will have a `Status` written against it. Since git commit SHAs are content-addressed and preserved across forks, shared upstream history, or multiple Shipit stacks tracking overlapping history, an attacker who can trigger a genuine, correctly-signed `status` webhook for a repository they control (e.g., a public fork of a tracked project, or any repo covered by the same GitHub App/organization installation) can cause identical-sha commits in unrelated stacks to receive attacker-influenced status/description/target_url content.

### Impact Explanation
This is a "payload for one repository mutating another's stack/commit" scenario. An attacker-controlled webhook write can create `Status` records (state, description, `target_url`) on commits belonging to stacks/repositories the attacker does not own, potentially flipping a commit from pending/failure to `success`, which feeds directly into `Commit#deployable?` and `schedule_continuous_delivery`, and can trigger deploy hooks (`Hook.emit(:deployable_status, ...)`) — i.e., it can influence whether an unrelated stack's commit is considered deployable. This matches the Critical bucket ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Exploitation requires the attacker to produce a genuinely GitHub-signed `status` webhook (they cannot forge `X-Hub-Signature` without the secret), meaning they need a repository under the same GitHub App/organization installation configured in Shipit, and a commit `sha` that collides with a commit already tracked by a victim `Stack`. SHA collisions across repos are realistic in common cases: forks preserving history, monorepo splits, multiple Shipit `Stack`s tracking the same underlying repository/branches, or shared vendored commits — not a cryptographic SHA1 break. The code-level flaw is unconditional and 100% reproducible in a unit test regardless of how the sha collision is obtained in practice.

### Recommendation
Scope the lookup by the webhook's authenticated repository, e.g. use the base `Handler#stacks` helper: `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so only commits belonging to stacks under the repository that produced/authenticated the webhook are mutated.

### Proof of Concept
Under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (minitest, no live GitHub):
1. Create 3 `Stack`/`Repository` fixtures for 3 distinct repositories.
2. Create 3 `Commit` records, one per stack, all sharing the identical `sha` value (e.g. `"a" * 40`).
3. Build a `status` webhook payload referencing only repository #1 (`repository.full_name` = repo #1's name) with that `sha`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `Shipit::Status.where(commit_id: [commit1.id, commit2.id, commit3.id]).count == 3` — i.e. all 3 stacks (`stack_id` values) received a new `Status`, not just the 1 stack tied to `repository.full_name` in the payload. This confirms `distinct stack_id count == 3 ≠ 1`, breaking the claimed binding.

### Citations

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
