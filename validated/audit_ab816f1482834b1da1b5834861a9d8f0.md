Based on my investigation, this is a valid, confirmed vulnerability.

### Title
`StatusHandler#process` writes GitHub status to every `Commit` row sharing a SHA across all repositories, bypassing repository scoping - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on the repository/stack that the webhook actually authenticated for. Any commit record in the database (belonging to *any* stack, for *any* repository) whose `sha` column matches the attacker-supplied `sha` gets a new `Status` written, which can flip `deployable?`/merge eligibility for a completely unrelated stack.

### Finding Description
The broken binding is: `authenticated_repository(webhook) == repository_of(commit_written_to)` must hold, but it does not.

- `WebhooksController#verify_signature` only proves that the payload was signed by the GitHub App/org matching `payload.dig('repository','owner','login')` [1](#0-0) . It says nothing about which `Commit` rows may be mutated.
- The base `Handler` class exposes a repository-scoped helper, `stacks`, built from `Repository.from_github_repo_name(repository_name)` [2](#0-1) , which other handlers are expected to use to scope their side effects to the stacks belonging to the authenticated repository.
- `StatusHandler#process` does **not** use that scoping. It queries the `Commit` table directly by `sha` alone: [3](#0-2) 
- `Commit belongs_to :stack` [4](#0-3)  and stacks track repositories independently; nothing prevents two different stacks (e.g., a victim's stack tracking `victim/repo` and an attacker-owned fork sharing history) from having `Commit` rows with an identical `sha` value, since git SHAs are content hashes shared across forks/clones of the same history.
- `commit.create_status_from_github!(params)` creates a `Status` row tied to that commit's stack and calls `add_status`, which re-evaluates `deployable_status`/`commit_status` hooks and can call `stack.schedule_merges` [5](#0-4) .

Exploit flow: the attacker owns (or forks) a repository that shares commit history with the victim's tracked repository (or otherwise arranges for a `Commit` row with a colliding `sha` to exist, e.g. via a shared upstream commit both stacks have already synced). The attacker's repo has a valid webhook secret for their own organization. The attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid signature for their own org, and a payload `{ "sha": "<shared-sha>", "state": "success", "context": "ci/circleci", "repository": {"full_name": "attacker/repo", "owner": {"login": "attacker-org"}} }`. `verify_signature` passes because it only checks the attacker's own org's signature. `StatusHandler#process` then finds *all* `Commit` rows with that `sha`, including the victim's, and writes a `success` status for `ci/circleci` to the victim's commit — regardless of whether `attacker/repo` has anything to do with the victim's stack.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate the payload structure and that the sender's org is legitimate for *its own* repository; none of them constrain which `Commit` rows `StatusHandler` may touch. The repository-scoping mechanism (`stacks`, `repository_name`) exists in the codebase but is simply unused by this handler.

### Impact Explanation
A `success` status for a context listed in the victim stack's `ci.require` (e.g., `ci/circleci`) can flip the victim commit out of "pending CI" state, changing `deployable?` and triggering `stack.schedule_merges` [6](#0-5) , potentially causing an unauthorized deploy, rollback, or merge for a repository/stack the attacker does not own and never authenticated a webhook for. This is a payload for one repository mutating another's commit/stack state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). The attack is repeatable against any stack whose tracked commits share a SHA with an attacker-accessible repository (forks, shared upstream history, cherry-picks with identical trees, etc.), and blast radius spans all tenants/stacks sharing git history with attacker-controlled repos.

### Likelihood Explanation
Preconditions: attacker needs (1) a repository they legitimately own/control with a valid webhook secret for their own org, and (2) a `Commit` row already present in the victim's stack with a `sha` also reachable/known to the attacker (trivially achievable via forking the victim's public repo — forks share identical commit SHAs for all shared history, and Shipit syncs commits via push/sync jobs that create `Commit` rows per stack). No privileged Shipit role, session, or victim secret is required. This is low-cost and fully repeatable — the attacker can pick any historical commit already synced in the victim stack and forge a `status` event from their own authenticated repo.

### Recommendation
Scope `StatusHandler#process` by the repository/stack that authenticated the webhook, mirroring the `stacks` helper already defined in the base `Handler` class, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack: stacks)`, so only commits belonging to stacks tracking the authenticated repository can receive the status update.

### Proof of Concept
Minitest plan (no live GitHub):
1. Seed a victim `Stack`/`Repository` (e.g., `victim/repo`) with `ci.require` including `ci/circleci`, and a `Commit` with `sha = "deadbeef..."` and no existing `ci/circleci` status (so `deployable?` is false / pending).
2. Seed a second, unrelated `Stack`/`Repository` (e.g., `attacker/repo`) and create a `Commit` on it with the **same** `sha = "deadbeef..."` (simulating shared git history via fork).
3. Build a `status` webhook payload: `{ "sha" => "deadbeef...", "state" => "success", "context" => "ci/circleci", "repository" => {"full_name" => "attacker/repo", "owner" => {"login" => "attacker-org"}} }`.
4. Stub `GithubHook#verify_signature` (or the equivalent org signature check) to return true only for `attacker-org`, simulating a legitimately signed webhook from the attacker's own org.
5. `assert_before = victim_commit.deployable?` (expect `false`/pending); process the payload through `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` or `POST :create`.
6. Reload `victim_commit`; `assert_equal 'success', victim_commit.status.state` for `ci/circleci`, and `assert victim_commit.deployable?` (or check `assert victim_commit.statuses.exists?(context: 'ci/circleci', state: 'success')`), proving the victim commit was mutated by a webhook that never authenticated `victim/repo`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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
