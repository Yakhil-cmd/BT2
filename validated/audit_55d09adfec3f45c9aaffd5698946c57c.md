This confirms the vulnerability. Every other handler (e.g. `PushHandler`) scopes its query through the `stacks` helper defined in `Shipit::Webhooks::Handlers::Handler`, which resolves `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` before touching any records [1](#0-0) [2](#0-1) . `StatusHandler#process`, however, never calls `stacks` or references `payload['repository']` at all — it looks up commits globally by bare `sha`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . `Commit#sha` has no uniqueness constraint scoped to `stack_id` enforced here, so any row in the `commits` table across all stacks/repositories that shares the SHA is updated.

The only gate before `process` runs is `WebhooksController#verify_signature`, which validates the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the attacker-controlled payload's `repository.owner.login` field [4](#0-3) [5](#0-4) . This only proves the request was signed by the GitHub App/webhook secret for the org that owns the attacker's own repository — it says nothing about which `sha` or `context` the payload references, and it never restricts `Commit.where(sha:)` to the sending repository. So a correctly-signed `status` event from a repository the attacker owns (in an org connected to the same GitHub App installation as Shipit) can carry any `sha`/`context`/`state` and will flip status rows for **any** commit in the database sharing that SHA, including a victim's stack's commit if that SHA happens to be shared (e.g. same upstream commit imported into two different Shipit-tracked repos/forks).

### Title
Cross-repository `status` webhook write via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare `sha` across the entire `commits` table with no repository/stack scoping, unlike every other webhook handler which resolves `stacks` from `payload['repository']['full_name']` first. An attacker who can get a validly-signed `status` webhook accepted for their own repository (any repo whose org shares a GitHub App/webhook secret with Shipit) can write a `codecov/project` `success` status onto a victim's commit row whenever the SHA is shared between the attacker's repo and the victim's tracked stack, silently flipping the victim commit's `deployable?`/`blocked?` state.

### Finding Description
The broken binding is: **a status update authorized for repository A should only be applied to commits belonging to repository A's stack(s)** — i.e. `commit.stack.repository == payload['repository']`. This invariant holds for `PushHandler` (`stacks` scoped via `Repository.from_github_repo_name(repository_name)`) but not for `StatusHandler`, which does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no reference to `payload['repository']` at all.

`WebhooksController#verify_signature` only authenticates that the sender controls the webhook/App secret for the organization named in the payload's own `repository.owner.login` — it does not, and cannot, verify that the `sha` in the payload actually belongs to that repository. Once signature verification passes, `StatusHandler` blindly matches every `Commit` row across all stacks with that `sha` and applies `create_status_from_github!`, which appends a new `Status`, recomputes `status`/`deployable?`/`blocked?` via `add_status`, and can trigger `stack.schedule_merges` [6](#0-5) .

Exploit flow: an attacker with a repo (or org) that shares a GitHub App installation/webhook secret with the Shipit host sends `POST /webhooks` with header `X-Github-Event: status` and a body whose `repository` block names the attacker's own repo (so `verify_signature` passes), but whose `sha` matches a commit SHA that also exists in a victim's Shipit-tracked stack (e.g. a shared open-source commit, cherry-pick, or a commit later adopted into both repos' histories), `context: codecov/project`, `state: success`. `StatusHandler` finds the victim's `Commit` row by that bare SHA and records the forged "success" status against it, potentially unblocking/enabling deploy or merge for a required status context it never actually satisfied on the victim's own CI.

### Impact Explanation
This lets one repository's signed webhook payload mutate another repository's/stack's commit-status state (`Status`/`deployable?`/merge scheduling), matching "Critical — payload for one repository mutating another's stack, commit, task or team." The write is a real `Status` record creation via `commit.create_status_from_github!` and can flip `Commit#deployable?`/`blocked?` and trigger `stack.schedule_merges`, i.e. an unauthorized influence over deploy/merge decisions for a stack the attacker does not control. It is repeatable for any SHA collision the attacker can discover or engineer between their own repo and a target stack.

### Likelihood Explanation
Requires the attacker's `status` webhook to pass signature verification (attacker must own/control a repository under a GitHub App installation or org whose webhook secret is recognized by `Shipit.github(organization: repository_owner)`), and requires a SHA collision between that repository and the victim's Shipit-tracked stack — realistic for forks, mirrors, vendored/shared commit histories, or monorepo splits where the same commit is pushed to multiple remotes tracked by different Shipit stacks. Given those preconditions, the attack costs a single crafted HTTP request and is fully repeatable.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve `stacks` (or the owning `Repository`) from `payload['repository']['full_name']`, then restrict the `Commit` lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or join through `stack: :repository`) before calling `create_status_from_github!`, so a status can only mutate commits belonging to the repository that authenticated the webhook.

### Proof of Concept
minitest plan (no live GitHub):
1. Create `repository_a` (attacker-owned, e.g. `attacker/attacker-repo`) with `stack_a`, and `repository_v` (victim, e.g. `victim/victim-repo`) with `stack_v` requiring `codecov/project` as a required status.
2. Create `commit = shipit_commits(:some_sha)` (or a factory commit) with the SAME `sha` value attached to both `stack_a` and `stack_v` (simulate the shared-SHA precondition): `commit_a = stack_a.commits.create!(sha: shared_sha, ...)`, `commit_v = stack_v.commits.create!(sha: shared_sha, ...)`.
3. Assert precondition: `assert_not commit_v.deployable?` (or assert `commit_v.status.simple_state` is not success/required context missing).
4. Build a payload whose `repository.full_name` is `repository_a.full_name` (i.e. authenticated for repo A) but `sha: shared_sha`, `context: 'codecov/project'`, `state: 'success'`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller signature check, which is out of scope of this model-level test).
6. Assert the binding broke: `commit_v.reload.statuses.where(context: 'codecov/project').exists?` is `true`, and `commit_v.deployable?`/`blocked?` state changed, even though the payload never named `repository_v`. Compare against `commit_a` to show both received the write despite only `repository_a` being authenticated — the equality `commit.stack.repository.full_name == payload['repository']['full_name']` fails for `commit_v` yet the status was still written.

### Citations

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
