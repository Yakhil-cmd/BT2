### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table with no repository filter, unlike other webhook handlers that scope lookups through the `stacks`/`repository_name` helper. Because git SHAs are content-addressed and are legitimately shared across forks (and any repo whose history overlaps another's), a GitHub status event that is validly signed for one repository can flip the `ci/kubernetes` status of a commit belonging to a completely different stack, including one flagged as a production environment.

### Finding Description
The broken binding: `params.sha` (attacker-controlled, from a webhook the attacker legitimately triggers for their own repository) is treated as globally unique, i.e. the code implicitly assumes `Commit.where(sha: params.sha).stack.repository == payload['repository']`. That equality is never checked.

Code path:
1. `Shipit::WebhooksController#create` → `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) validates the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of the (GitHub-authored, signed) payload `repository.owner.login`. This authenticates "a real GitHub webhook for an org/app Shipit trusts," not "a webhook for a specific repository."
2. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) then runs:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a table-wide, unscoped lookup — it never consults `payload.dig('repository','full_name')` or the `stacks`/`repository_name` helper defined in the shared `Handler` base class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that other handlers use to constrain effects to the authenticating repository.
3. `Commit#create_status_from_github!` → `add_status` (`app/models/shipit/commit.rb:165-169, 366-386`) applies the new status, recomputes `status`/`deployable?`/`blocked?`, and can trigger `stack.schedule_merges` — i.e., real ship/block/merge side effects on whatever stack owns that commit row, regardless of which repository authenticated the request.

Exploit flow: an attacker who owns or forks a repository sharing commit history with the victim's production stack (e.g., a fork, which retains identical commit SHAs for shared history) can call GitHub's Statuses API on their own repo for a SHA that also exists as a `Commit` row in the victim's production stack, with `context: ci/kubernetes`, `state: success`. GitHub signs and delivers this webhook legitimately for the attacker's own repository. `verify_signature` passes because it only checks the signature against the org/app secret, not that the SHA belongs to that repository. `StatusHandler` then writes the `success` status onto the victim's commit, flipping `deployable?`/`blocked?` for a production stack.

None of the existing guards prevent this: `verify_signature` authenticates org/app identity, not repo-to-SHA binding; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema validates payload shape, not repository scope; there is no `require_permission!`/`stacks` check in `StatusHandler` at all (contrasted with the `Handler#stacks` helper that exists precisely for this purpose but is unused here).

### Impact Explanation
A payload validly authenticated for repository A can mutate the deployability/status of a commit belonging to a different stack (repository B), including a production environment stack. This directly matches the in-scope Critical category "a payload for one repository mutating another's stack, commit, task or team" and can result in an unauthorized deploy or a wrongful block of a legitimate deploy on a production stack. The blast radius spans any two stacks/tenants whose commit history overlaps (typically forks or mirrors within the same GitHub App/org installation), and is repeatable for every shared SHA.

### Likelihood Explanation
Requires: (a) attacker controls a repository whose git history overlaps a victim's tracked stack (realistic for forks, which is a normal, unprivileged GitHub capability), and (b) that repository is covered by the same Shipit-trusted GitHub App/org installation so `verify_signature` succeeds. Attacker cost is low — pushing/using the GitHub Statuses API on their own repo for a shared SHA, no Shipit credentials needed. Feasibility depends on the org/webhook topology but requires no secret material.

### Recommendation
Scope `StatusHandler#process` (and symmetrically, any similar handler) to only update commits belonging to the stack(s) matching the authenticating `payload['repository']['full_name']`, e.g. via the existing `stacks` helper: `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, rejecting/ignoring matches outside that repository's stacks.

### Proof of Concept
minitest plan (no live GitHub):
1. Create two `Shipit::Stack` records, `victim_stack` (repository `org/victim`, `environment: 'production'`, `required_statuses: ['ci/kubernetes']`) and `attacker_stack` (repository `org/attacker`).
2. Create a `Shipit::Commit` on `victim_stack` with `sha: 'a' * 40`, currently pending/undeployable.
3. Build a status webhook payload with `repository.full_name = 'org/attacker'`, `sha: 'a' * 40`, `context: 'ci/kubernetes'`, `state: 'success'`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, as it is out of scope for this handler-level test).
5. Assert before: `victim_commit.reload.deployable?` is `false` (or state != success).
   Assert after: `victim_commit.reload.deployable?` becomes `true` / status is `success`, even though the payload's `repository.full_name` was `org/attacker`, not `org/victim` — proving the write crossed repository boundaries. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
