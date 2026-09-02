### Title
`StatusHandler#process` mutates `Commit`/`Status` rows for any sha match regardless of `repository.full_name`, bypassing repository-scoping entirely - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` directly and calls `create_status_from_github!` on every match, without ever calling `Repository.from_github_repo_name(repository_name)` or filtering by the payload's `repository.full_name`. Any GitHub organization/app trusted by `Shipit.github(organization:)` for signature verification — even one with zero `Shipit::Repository` records — can send a `status` webhook whose `sha` collides with a tracked commit and have Shipit create/replicate a `Status` on that commit, across every stack sharing that sha.

### Finding Description
The broken binding, stated as an equality that should hold but does not: `Commit rows mutated by StatusHandler#process == Commit rows belonging to a Repository matching payload['repository']['full_name']`. In this handler that equality is never enforced.

Code path: `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0)  after `verify_signature`, which authenticates only that the payload was signed by the org named in `repository.owner.login` (`repository_owner`) — it does not check that a `Shipit::Repository` exists for `repository.full_name` [2](#0-1) . `Handler.call` builds params via `ExplicitParameters` and invokes `process` [3](#0-2) . The base `Handler` class provides a `stacks` helper that does look up `Repository.from_github_repo_name(repository_name)` and scopes to that repository's stacks, falling back to `Stack.none` if unknown [4](#0-3) , and pull-request handlers use this `stacks` scoping. `StatusHandler#process`, however, never calls `stacks` or `Repository.from_github_repo_name`; it does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . `create_status_from_github!` calls `add_status`, which replicates the GitHub status into `statuses`, reloads the commit, recomputes `status`, and fires `Hook.emit(:commit_status, ...)` / `:deployable_status` and potentially `stack.schedule_merges` [6](#0-5) [7](#0-6) .

Attacker request: an unprivileged attacker who controls (or creates) a GitHub org/app that is registered in Shipit's `github_apps`/`github` config for signature purposes but has no `Shipit::Repository` row — or, more realistically, any org whose GitHub App installation is trusted by `Shipit.github(organization: repository_owner)` — sends a `status` event webhook with `repository.full_name` set to an arbitrary/untracked repo and `sha` equal to a sha that happens to exist in the target's tracked `Commit` table (sha collision across repos is a real risk since commits are looked up globally by sha, not scoped by repository). `verify_signature` passes because it only checks the org's key, not that the repo is tracked. `StatusHandler#process` then updates status for all matching commits across all stacks sharing that sha.

Existing guards fail because: `verify_signature` is a per-organization signature check, not a per-repository authorization check [8](#0-7) ; `drop_unhandled_event` only checks event type; the `ExplicitParameters` schema validates parameter shape, not repository identity; and `StatusHandler` simply does not use the `stacks`/`Repository.from_github_repo_name` scoping that other handlers use.

### Impact Explanation
An org trusted merely for webhook signature verification — independent of whether it owns any tracked repository in Shipit — can trigger creation of `Status` rows on arbitrary tracked `Commit` records purely via sha match, with no `Repository` binding check. This can flip CI/commit state (`success`/`failure`/`pending`) on stacks it doesn't own, potentially unblocking deploys/merges (`stack.schedule_merges`) or hiding CI failures, which affects deploy/merge decisions of a different, legitimate stack/repository. This matches "a payload for one repository mutating another's stack, commit ... " — Critical.

### Likelihood Explanation
Exploitability requires: (1) an attacker-controlled org/app that Shipit's `Shipit.github(organization:)` config can validate a signature for (this could be the attacker's own GitHub App/org registered with Shipit for legitimate but unrelated purposes, or any org onboarded to Shipit at all, even without an associated `Repository` record yet), and (2) a sha collision or an attacker crafting a commit whose sha matches one already tracked (feasible if attacker can push the exact same commit content, e.g. via fork/cherry-pick of a public commit, to their own repo and then send a forged `status` payload referencing their own repo/org but the shared sha). Given the low bar (no Shipit repository, no maintainer privilege, no session/token needed — only a valid signature from a trusted org), this is realistically triggerable and repeatable per sha the attacker can source.

### Recommendation
In `StatusHandler#process`, scope the update to the repository named in the payload, e.g. resolve `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` and only mutate `Commit`s belonging to that repository's stacks (mirroring the `stacks` helper already defined in the base `Handler` class), rather than a global `Commit.where(sha: ...)` scan.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not create status for commit outside the payload's repository" do
  stack = shipit_stacks(:shipit)
  commit = stack.commits.create!(sha: 'a' * 40, message: 'test')

  Shipit::Repository.stub :from_github_repo_name, nil do
    payload = {
      'sha' => commit.sha,
      'state' => 'success',
      'repository' => { 'full_name' => 'unknown-org/unknown-repo', 'owner' => { 'login' => 'unknown-org' } }
    }

    assert_no_difference -> { commit.statuses.count } do
      Shipit::Webhooks::Handlers::StatusHandler.call(payload)
    end
  end
end
```
Currently this assertion fails: `StatusHandler#process` never calls `Repository.from_github_repo_name`, so the stub is irrelevant, and `commit.statuses.count` increases by 1 — demonstrating the equality "`Commit` mutated == `Commit` belongs to `Repository` matching `payload['repository']['full_name']`" does not hold.

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
