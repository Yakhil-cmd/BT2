### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository filter and applies the attacker-supplied GitHub status to every matching `Commit` across every `Stack`/`Repository` in the installation. Because `Commit#sha` is not required to be globally unique and the webhook signature check only verifies that the *payload's own* `repository.owner.login` matches a known GitHub App installation — not that the SHA belongs to that repository — an attacker who controls a repository (or fork) can craft a `status` webhook with a colliding SHA and a forged `release/gate` `failure` state that mutates a victim's production stack's commit status.

### Finding Description
The broken binding is: for every `commit` mutated by `StatusHandler#process`, it must hold that `commit.stack.repository.full_name == payload['repository']['full_name']` (the repository whose HMAC secret verified the webhook). This is never checked.

Code path:
- `Shipit::WebhooksController#create` parses the raw JSON and dispatches to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` only proves the request was signed by the GitHub App belonging to `repository_owner` (`params.dig('repository','owner','login')`) — it authenticates *who sent the payload*, not which SHA/commit the payload is allowed to affect [2](#0-1) .
- `Handler` (base class) exposes a `stacks` helper that *does* correctly scope by `Repository.from_github_repo_name(repository_name)` [3](#0-2) , but `StatusHandler#process` does not use it. Instead:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 
This queries the `commits` table globally by SHA with no join/filter on `stack_id`/`repository_id`.
- `create_status_from_github!` then writes a `Status` row tied to that commit's own `stack` and recomputes `status` via `add_status`, which fires deploy-blocking side effects (`stack.schedule_merges`, `Hook.emit(:deployable_status, ...)`) whenever the simple state changes [5](#0-4) [6](#0-5) .
- Whether a status is required/blocking is stack-configuration-driven (e.g. a required `release/gate` context on the victim's production-environment stack), and `Commit#blocked?`/`#deployable?` are computed purely from `statuses` rows on that commit, independent of which repository actually posted the status [7](#0-6) .

Exploit flow: an attacker pushes/forks a commit that happens to share a SHA with a commit already tracked in a victim's production Shipit stack (SHA collision across repos requires either coincidence, or — more practically — the attacker discovering/reusing a SHA that is already present in the victim stack's `commits` table, e.g. by observing a public mirror/fork relationship, cherry-picked commits, or a shared upstream). The attacker then sends a signed `status` webhook from their own (attacker-controlled, correctly-signed) repository with `sha` set to that shared value, `context: release/gate`, `state: failure`. `verify_signature` passes because it validates against the attacker's own repository's webhook secret/App installation, not the victim's. `StatusHandler#process` then finds the victim's `Commit` row (matching by bare SHA) and writes a `failure` status onto it, flipping `blocked?`/`deployable?` on the victim's production stack.

Existing guards do not stop this: `verify_signature` authenticates the sender's own repo, not the SHA's ownership; `ExplicitParameters` only validates the shape of `sha`/`context`/`state`, not their relationship to the sending repository; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler`.

### Impact Explanation
An attacker with no privileges on the victim's Shipit instance can write a `Status` record onto a victim stack's `Commit` that they do not own, forcing a required `release/gate` context to `failure`. On a production-environment stack, this can block deploys/merges (`blocked?`/`deployable?` flip) or, depending on how the victim's automation reacts to `deployable_status`/`commit_status` hooks, trigger rollback/gating logic — a payload for one repository mutating another's stack/commit, matching the "Critical" impact category (cross-tenant write via an unscoped lookup). The blast radius is any Shipit stack whose commits share a SHA with an attacker-reachable repository; this is repeatable per matching SHA and is not limited to a single victim.

### Likelihood Explanation
Preconditions: (1) attacker can send a validly-signed webhook from a repository/GitHub App installation they control (trivial — anyone can create a repo and configure the app or, if the app installation is shared/broad, use it directly); (2) attacker must produce a `sha` that also exists as a `Commit` row in the victim's stack — this is the real bottleneck. In real deployments this is plausible when stacks track forks/mirrors of the same upstream (shared commit history → identical SHAs across many repositories in the same Shipit instance), which is a common Shipit setup (mono-org forks, mirrored release repos). Attacker cost is a single HTTP POST; the attack is fully repeatable for any known/guessed shared SHA.

### Recommendation
Scope `StatusHandler#process` (and symmetrically check `CheckSuiteHandler`/other SHA-keyed handlers) to only the commits belonging to the repository that authenticated the webhook, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `stacks` helper from `Handler` (already correctly implemented and available), which filters via `Repository.from_github_repo_name(repository_name)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repo_a` (`Repository`, owner `attacker/repo`) and `stack_a` under it; create `repo_b` (`Repository`, owner `victim/repo`) and `stack_b` under it, `stack_b.environment = 'production'`, with `stack_b.required_statuses = ['release/gate']` (or equivalent config making `release/gate` a blocking status).
2. Create `commit_b` under `stack_b` with `sha = "deadbeef..."` (currently `success`/deployable, i.e., `commit_b.blocked?` is `false` and `commit_b.deployable?` is `true`).
3. Create `commit_a` under `stack_a` with the **same** `sha = "deadbeef..."` (simulating the attacker's own repo containing an identical SHA), which is what a signed webhook from `repo_a` is entitled to affect.
4. Build `params = { 'sha' => 'deadbeef...', 'state' => 'failure', 'context' => 'release/gate', 'repository' => { 'full_name' => 'attacker/repo' } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(params)` directly (bypassing controller-level signature verification, as permitted — the finding is about `process`, not signature bypass).
6. Assert the equality that should hold and currently fails:
   - Before: `commit_b.reload.deployable?` is `true`, `commit_b.blocked?` is `false`.
   - After: `commit_b.reload.deployable?` becomes `false` and/or `commit_b.blocked?` becomes `true`, even though the webhook's `repository.full_name` (`attacker/repo`) never equals `stack_b`'s repository (`victim/repo`).
   - Explicit assertion: `assert_not_equal params['repository']['full_name'], commit_b.stack.repository.full_name` (proving the mismatch) while `assert commit_b.statuses.where(context: 'release/gate', state: 'failure').exists?` (proving the unauthorized write occurred).

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
