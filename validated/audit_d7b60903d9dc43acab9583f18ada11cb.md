### Title
Cross-tenant Commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target `Commit` rows purely by `sha`, with no check that the commit's `stack.repository` matches the webhook's authenticated `repository.full_name`. Because git commit SHAs are content-derived and identical across any repositories that share the same commit object (forks, mirrors, or a deliberately re-pushed copy of a public commit), an attacker who owns any repository covered by a Shipit-trusted GitHub App/webhook installation can post a real, GitHub-signed `status` event for a SHA that also exists in an unrelated victim Stack, causing Shipit to create a `Status` on the victim's `Commit`, which in turn fires `Hook.emit(:commit_status, stack, ...)` and `Commit#broadcast_update` with attacker-controlled `state`/`description`/`target_url` under the victim stack's identity.

### Finding Description
The binding that should hold is:
`Commit#stack.repository.full_name == payload.dig('repository', 'full_name')` for every `Commit` mutated by a `status` webhook.

Tracing the code shows this binding is never checked:

- `WebhooksController#create` parses the raw JSON body and dispatches to registered handlers for the event type, after `verify_signature` confirms the payload was HMAC-signed by the org identified in `repository_owner` (`Shipit.github(organization: repository_owner)`), and `drop_unhandled_event`/`check_if_ping` short-circuit other cases. [1](#0-0) 

- Every other handler in the base `Handler` class scopes lookups by repository via `stacks`, which resolves `Repository.from_github_repo_name(repository_name)&.stacks`, tying results to the webhook's own `repository.full_name`. [2](#0-1) 

- `StatusHandler#process`, however, bypasses this scoping entirely and queries `Commit` globally by `sha`: [3](#0-2) 

- For every matching `Commit` (regardless of which `Stack`/`Repository` it belongs to), `create_status_from_github!` → `add_status` creates a `Status`, and — if the state changed — fires `Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status))` using that commit's own `stack`, with `payload` (including attacker-controlled `description`/`target_url`/`state` from `Status.replicate_from_github!`) fully attacker-controlled. [4](#0-3) [5](#0-4) 

- `Status` also triggers `after_commit :broadcast_update`, delegated to `commit`, pushing a PubSub update on the victim stack's channel to any subscriber of that stack's real-time status stream. [6](#0-5) 

Root cause: `sha` is content-derived and not globally unique to one repository — any repository that shares a commit object (a fork, a mirror, or a manually recreated identical commit pushed elsewhere) produces the same SHA. Since GitHub fires a real, correctly-signed `status` webhook whenever *any* repository (including one an attacker fully controls) receives a `POST /repos/:owner/:repo/statuses/:sha` call, an attacker with write access to their own repository — provided that repository's org/App installation is one Shipit trusts (has a configured `webhook_secret`) — can obtain a legitimately signed webhook carrying a SHA that also exists in a completely unrelated Stack's commit history, plus arbitrary `state`, `description`, `target_url`, and `context` values.

`verify_signature` and `drop_unhandled_event` only validate that the request truly came from GitHub for the organization named in the payload; they do nothing to ensure the *commit* being updated actually belongs to that organization's repository. `ExplicitParameters` in `StatusHandler` only validates types/presence of fields, not repository ownership. No other guard exists between the verified payload and the unscoped `Commit.where(sha:)` lookup.

### Impact Explanation
An attacker who controls (or has push/status-API access to) any repository whose org is registered with Shipit can:
- Create arbitrary `Status` rows attributed to a victim's `Commit`/`Stack`, mutating a record for a repository that did not authenticate the write.
- Trigger `Hook.emit(:commit_status, ...)` and any configured outbound Slack/webhook integrations for the victim stack with attacker-chosen `description`/`target_url` strings, forging notifications under the victim's identity.
- Force a real-time PubSub broadcast (`broadcast_update`) visible to any subscriber of the victim stack's public status stream.
- Because `add_status` also triggers `stack.schedule_merges` on `pending`/`success` transitions, a forged `success` status can influence merge-request auto-merge logic for the victim stack — an unauthorized effect on deploy-adjacent automation.

This is repeatable against any repository/commit combination sharing a SHA that the attacker can reproduce (trivial for forks/mirrors of public repos, or any commit the attacker can literally re-create/re-push since git commits are fully public data for public repos). This matches the "payload for one repository mutating another's stack/commit" Critical category.

### Likelihood Explanation
- Preconditions: attacker must have write/status-API access to at least one repository whose organization is configured in Shipit with a valid GitHub App/webhook installation (this is the same bar as "own a repository that emits webhooks," per the threat model), and the target Stack A commit's SHA must be knowable/reproducible (trivial for any public repository, since git objects are public and forking/copying reproduces identical SHAs).
- No Shipit secrets, sessions, or API tokens are required — the attacker relies on GitHub itself to sign the forged event, exactly as it would for a legitimate status update on their own repo.
- Cost is low: fork/mirror the target commit into an attacker-controlled repo (or directly `POST` a status via the GitHub API for a self-owned repo containing that commit), which is unprivileged and repeatable at will.

### Recommendation
Scope `StatusHandler#process` to the webhook's authenticated repository instead of querying globally by `sha`. Use `stacks` (already resolved from `repository_name`) to find the relevant `Stack`(s), then look up `Commit`s within those stacks only, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently scope through `Repository.from_github_repo_name(repository_name)&.stacks&.joins(:commits)&.where(shipit_commits: { sha: params.sha })`, ensuring every `Commit` mutated belongs to a `Stack` whose `Repository` matches the webhook's own `repository.full_name`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Create two `Stack`s backed by two different `Repository` records (`victim/repo` and `attacker/repo`), each with a `Hook` listening on `commit_status`.
2. Create a `Commit` with `sha: "deadbeef..."` belonging to the victim stack (simulate shared SHA due to a fork/mirror) — do **not** create any commit with that SHA under the attacker's stack.
3. POST a `status` webhook to `/webhooks` with `X-Github-Event: status`, a valid signature for `attacker`'s org, and body `{"sha": "deadbeef...", "state": "failure", "description": "ATTACKER CONTROLLED", "target_url": "http://evil.example.com", "repository": {"full_name": "attacker/repo", "owner": {"login": "attacker"}}}`.
4. Assert:
   - `Hook.expects(:emit).with(:commit_status, victim_stack, has_entries(commit_status: has_attributes(description: "ATTACKER CONTROLLED", target_url: "http://evil.example.com")))` fires — i.e., `victim_stack.repository.full_name` ("victim/repo") is asserted to equal `"attacker/repo"` from the payload (the binding), and the test shows this equality is false yet the hook still fires.
   - `victim_commit.reload.statuses.last.description == "ATTACKER CONTROLLED"`.
5. A regression assertion after the fix: the same POST results in `assert_no_enqueued_jobs(only: EmitEventJob)` / no new `Status` on the victim commit, because the handler is scoped to `attacker/repo`'s stacks and finds no matching commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
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

**File:** app/models/shipit/commit.rb (L366-377)
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
```

**File:** app/models/shipit/status.rb (L19-21)
```ruby
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```
