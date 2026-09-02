### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a webhook authenticated for one repository mutate commit status/merge state for any other stack sharing that SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by bare `sha` with no join or filter against the repository/organization that the webhook signature actually authenticated, then calls `commit.create_status_from_github!` for every matching row across every stack in the database. Because `Commit#add_status` triggers `stack.schedule_merges` and recomputes `deployable?`/`blocked?` whenever the aggregated status changes, an attacker who can get any validly-signed `status` webhook accepted by Shipit (for their own onboarded org/repo) can flip the required `ci/test` context for a completely different, unrelated stack whose commit history happens to share that SHA (e.g. via a fork).

### Finding Description
The broken binding is: `repository_owner_that_authenticated_the_signature == stack.repository.owner_for_every_Commit_row_touched_by_params.sha`. This should be an invariant but is never checked.

Trace:
- `Shipit::WebhooksController#verify_signature` computes `repository_owner` purely from the JSON payload (`params.dig('repository','owner','login')`) and verifies the HMAC using `Shipit.github(organization: repository_owner).verify_webhook_signature`, i.e., it authenticates that the request was signed with the webhook secret configured for that one organization. [1](#0-0) [2](#0-1) 
- Once that check passes, `Shipit::Webhooks.for_event(event)` dispatches to `StatusHandler#process`, which never re-reads `params['repository']` at all - it only uses `params.sha`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
- `Commit.where(sha: ...)` is a global, unscoped query across the entire `commits` table - it can match rows belonging to any `Stack`/repository, not just the one whose owner passed signature verification.
- `Commit#create_status_from_github!` → `#add_status` recomputes `status`, and when `previous_status.simple_state != new_status.simple_state` it calls `stack.schedule_merges if new_status.pending? || new_status.success?`, and also emits `deployable_status`/`commit_status` hooks. [4](#0-3) 
- `deployable?` and `blocked?` are derived live from `stack.blocking_statuses`/`stack.required_statuses` against the commit's current aggregated `status`, so a newly-injected `failure` status for context `ci/test` immediately changes `blocked?`/`deployable?` for any stack that treats `ci/test` as required/blocking, with no re-check of which repository actually owns that commit. [5](#0-4) 

Exploit flow: attacker needs a webhook that Shipit will accept as validly signed. That requires the attacker to control (or have legitimately onboarded) some organization/repo that Shipit already trusts via `Shipit.github(organization: ...)` - the signature check is scoped to whichever owner is named in the payload, using that owner's configured `webhook_secret`. Given a repo they legitimately own/administer with a real GitHub status event delivered to Shipit (e.g. a fork of the victim's public repository, which shares identical commit SHAs for the common ancestry), the attacker can produce or trigger a `status` event with `context: ci/test`, `state: failure` for a SHA that is shared with the victim's tracked repository history. Because `StatusHandler#process` never checks that the commit's `stack`/repository matches the authenticated payload's `repository`, the victim stack's `Commit` row for that same SHA is updated too.

Existing guards do not prevent this: `verify_signature` only proves the payload was signed by *some* trusted owner, not that the owner matches every `Commit` row that will be touched; `ExplicitParameters` (`params do ... end`) only validates payload shape (`sha`, `state`, `context`, etc.), not repository scope; there is no `stacks`/`repository` scoping anywhere in `StatusHandler`.

### Impact Explanation
A cross-tenant write: a status authenticated for org/repo A can flip the required-context state (and therefore `deployable?`/`blocked?`, and can invoke `stack.schedule_merges`) for a stack belonging to org/repo B, with `merge_queue_enabled: true` amplifying the effect into actual merge-queue advancement or blocking. This is exactly the listed critical category "a payload for one repository mutating another's stack, commit, task or team," and can produce an unauthorized block of legitimate merges/deploys (denial of a specific merge) or, in the success-state variant, an unauthorized ship/merge advance. It is repeatable against any stack whose commit history intersects (via forks or otherwise) a SHA the attacker can get a signed status delivered for, so the blast radius spans every stack sharing history with an attacker-reachable repository.

### Likelihood Explanation
Preconditions: the attacker must have at least one repository/org that is itself onboarded into Shipit's GitHub App configuration (so a `status` webhook from it passes `verify_signature`), and a SHA collision with the victim's tracked repository, which is trivially achieved via a public fork (forks share full commit history/SHAs with upstream). No secrets, sessions, or API tokens of the victim's org are needed. This is a low-cost, repeatable attack limited only by needing at least one legitimately-configured Shipit tenant under attacker control and a shared-history SHA with the target stack.

### Recommendation
Scope the status/check lookup by repository, not bare SHA: `StatusHandler#process` (and the analogous check-run handler) must filter `Commit` by the `stack`(s) whose `repository` matches `params.dig('repository','full_name')` (or owner+name) from the authenticated payload, e.g. `Commit.joins(:stack).merge(Stack.where(repository: expected_repo)).where(sha: params.sha)`, before calling `create_status_from_github!`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative):
1. Create `stack_a` (repo `attacker/foo`) and `stack_b` (repo `victim/bar`, `merge_queue_enabled: true`, `required_statuses: ['ci/test']`).
2. Create `Commit.create!(stack: stack_a, sha: 'deadbeef'*5)` and `Commit.create!(stack: stack_b, sha: 'deadbeef'*5)` (same SHA, simulating shared fork history).
3. Assert binding before: `stack_b.commits.last.deployable?` is whatever pre-state (e.g. `true` after a prior success status), i.e. `assert_equal true, stack_b.commits.last.deployable?` and confirm the request's authenticated owner is `attacker` (`params.dig('repository','owner','login') == 'attacker'`), not `victim`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new.process(sha: 'deadbeef'*5, context: 'ci/test', state: 'failure', repository: { full_name: 'attacker/foo', owner: { login: 'attacker' } })` (bypassing controller-level signature check to isolate the handler, matching the "no repository scoping" claim).
5. Assert binding after: `stack_b.commits.last.reload.deployable?` is now `false` / `blocked?` is `true`, proving a payload authenticated for `attacker/foo` mutated `stack_b` (owned by `victim/bar`), which never authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
