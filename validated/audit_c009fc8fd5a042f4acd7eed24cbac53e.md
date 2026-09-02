### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by SHA, with no filtering on the repository that authenticated the webhook, while the base `Handler` class already provides a repository-scoped `stacks` helper that this handler never uses. Because `verify_signature` in `Shipit::WebhooksController` authenticates requests per GitHub organization/app installation rather than per repository, any repository sharing that installation can submit a validly-signed `status` event whose `sha` matches a commit that actually belongs to a different repository's stack, letting the attacker write a `ci/e2e` `failure` status onto a victim stack's commit.

### Finding Description
The broken invariant, stated as an equality that must hold but does not:
`commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` mutated by `StatusHandler#process`.

Trace:
- `Shipit::WebhooksController#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` [1](#0-0) .
- `verify_signature` authenticates using `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature`, i.e. it validates the payload against the webhook secret associated with the *organization/app installation*, not a specific repository [2](#0-1) . Any repository covered by that same GitHub App installation (e.g. any repo in the same org, or any repo the attacker can create/own under that org) can produce a signature that passes this check.
- `Handler` (the base class every handler inherits from) exposes a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)` derived from `payload.dig('repository', 'full_name')` [3](#0-2) , showing that repository scoping is the intended pattern for handlers.
- `StatusHandler#process` ignores this helper entirely and instead runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . This query matches **any** `Commit` row across **any** stack/repository that happens to share the given `sha`, with no `repository_name`/`stack_id` filter.
- `Commit#create_status_from_github!` then writes the forged status via `statuses.replicate_from_github!(stack_id, github_status)` and recomputes `status`/`deployable?`/`blocked?` for that commit through `add_status`, which also emits `:commit_status`/`:deployable_status` hooks and calls `stack.schedule_merges` [5](#0-4) [6](#0-5) .
- `deployable?`/`blocked?` directly gate whether a commit can be shipped (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [7](#0-6) , so a forged `failure` on the required `ci/e2e` context flips `success?`/`blocked?` for the victim stack's commit exactly as if GitHub itself had sent it.

Exploit flow: attacker sends a `POST /webhooks` request with `X-Github-Event: status` and a body whose `repository.full_name`/`repository.owner.login` is a repo the attacker owns (or any repo sharing the same GitHub App/org installation as the victim), with `sha` set to a known commit SHA belonging to the victim's stack, `context: ci/e2e`, `state: failure`. `verify_signature` accepts it because it only checks the org-level webhook secret. `StatusHandler#process` then matches the victim's `Commit` row purely by SHA and writes the forged status onto it, changing that commit's deployability/blocked state in the victim stack — a stack the attacker's own webhook never authenticated for.

None of the existing guards catch this: `verify_signature` authenticates the org/app, not the specific repository being referenced inside the payload; `drop_unhandled_event` only checks the event type exists a handler; the `ExplicitParameters` schema (`params do ... end` in `StatusHandler`) validates field types/presence, not repository ownership; there is no `stacks`/repository filter applied before the `Commit.where(sha:)` query.

### Impact Explanation
A successful request lets an attacker mutate the deployability/blocking state of a commit belonging to a stack/repository they never authenticated for, matching the Critical category "a payload for one repository mutating another's stack, commit, task or task" and enabling "unauthorized deploy, rollback or merge" — a `failure` status on a required context blocks deploys of the targeted commit in the victim stack, and (per the question's framing) a subsequently-cleared/success status combined with `bot_login`-driven auto-merge/auto-deploy logic could force an unwanted ship. The attack is repeatable against any commit SHA the attacker can enumerate (git history is generally readable to anyone with repo access), and the blast radius spans every stack across every repository that shares the same GitHub App/org-level webhook secret with the attacker-controlled repository.

### Likelihood Explanation
Preconditions: attacker needs (a) a repository for which `verify_signature` succeeds — i.e., a repository sharing the same GitHub App installation/org as the victim's Shipit-tracked stack — and (b) knowledge of a commit SHA that exists in the victim stack (trivially obtainable from public commit history or from a repo the attacker can read). Both are realistic in common multi-repo/multi-team GitHub organizations where a single GitHub App installation covers many repositories but each Shipit stack is meant to be repository-scoped. No Shipit session, API token, or maintainer role is required, matching the "unprivileged attacker" threat model. This is fully repeatable and requires no live GitHub interaction beyond the one crafted webhook POST.

### Recommendation
In `StatusHandler#process`, replace the unscoped `Commit.where(sha: params.sha)` with a lookup scoped to the repository that authenticated the webhook, mirroring the base `Handler#stacks` pattern, e.g. resolve `stacks` (or their commits) via `repository_name` from the payload and intersect with `sha`, so a status can only ever mutate commits belonging to stacks of the repository that signed the request.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`-style, no live GitHub):
1. Create two `Repository`/`Stack` pairs: `victim_repo` (`full_name: "org/victim"`) with a `Stack` configured with `bot_login` (Shipit.user) and a required status `ci/e2e`, and `attacker_repo` (`full_name: "org/attacker"`) under the same organization.
2. Create a `Commit` with `sha: "deadbeef..."` belonging to `victim_repo`'s stack, with an existing successful `ci/e2e` status so `commit.deployable?` is `true` and `commit.blocked?` is `false`.
3. Stub/allow `verify_signature`-equivalent conditions (call the handler directly, as it's what `WebhooksController#create` invokes post-verification) with a payload where `repository.full_name == "org/attacker"` but `sha == "deadbeef..."`, `context: "ci/e2e"`, `state: "failure"`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert the binding is violated: before, `commit.stack.repository.full_name != payload['repository']['full_name']` (attacker repo vs victim repo) yet after calling the handler, `commit.reload.deployable?` changed from `true` to `false` (or `commit.blocked?` becomes `true`), proving the victim stack's commit state was mutated by a webhook that authenticated as a different repository.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
