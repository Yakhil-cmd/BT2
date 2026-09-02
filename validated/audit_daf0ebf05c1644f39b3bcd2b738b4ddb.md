Confirmed: `Handler#stacks` (base class used by `PushHandler`, `CheckSuiteHandler`, and the `pull_request` handlers) scopes stacks strictly to `Repository.from_github_repo_name(repository_name).stacks`, i.e. only to stacks belonging to the repository named in the payload. `StatusHandler`, however, bypasses this scoping entirely and updates `Commit.where(sha: params.sha)` globally, across every stack/repository in the Shipit instance. [1](#0-0) [2](#0-1) 

### Title
Cross-repository commit status forgery via unscoped `sha` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to validate a webhook using the `organization`/`repository.owner.login` field taken from the *same* JSON payload it is about to verify, then checks the whole raw body's HMAC-SHA1 against that org's `webhook_secret`. This is sound as a signature check per se (any organization that owns a Shipit-installed GitHub App can produce a validly-signed `status` event for its own repository). The problem is downstream: unlike every other event handler, `Shipit::Webhooks::Handlers::StatusHandler#process` never uses the `repository`-scoped `stacks` helper that all sibling handlers rely on. It looks up target commits purely by `sha`, globally, across all stacks belonging to any repository/organization on the instance, and calls `commit.create_status_from_github!(params)` on every match.

### Finding Description
The base `Handler` class provides `stacks`, which resolves `Repository.from_github_repo_name(repository_name)&.stacks` — i.e., it binds any webhook-driven mutation to the specific repository named (and, transitively, authenticated) in the payload. `PushHandler` and `CheckSuiteHandler` both use this helper before touching any records: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, resolves the target purely from the untrusted `sha` field, with zero repository binding: [2](#0-1) 

`Commit#create_status_from_github!` unconditionally writes a new `Status` record (and, via `add_status`, can trigger `deployable_status`/`commit_status` hooks and `stack.schedule_merges`) for any commit matching that sha, regardless of which stack/repository owns it: [5](#0-4) 

The webhook signature only proves "this payload was produced by an organization that has a legitimate GitHub App installed on some repository tracked by this Shipit instance" — it does not prove, and nothing downstream checks, that the `sha` being updated actually belongs to that organization's repository. This is exactly the "organization that authenticated versus the repository that is written" binding break called out in scope: `verify_signature` binds trust to `repository_owner` (an org that can legitimately sign a payload), but `StatusHandler#process` writes to *any* commit sharing that sha, in *any* repository, breaking `organization_authenticated == repository_written`.

Because Git commit SHA1s are content-addressed and fully deterministic (author, committer, timestamps, tree, parents, message), an attacker who controls a repository with its own Shipit-integrated GitHub App (their own org/app installation, fully legitimate, no privileged access to the victim needed) can:
1. Read (or otherwise obtain) the exact tree/commit metadata of a target commit in the victim's tracked repository (commits are public information for public repos, or already visible to the attacker if it's shared/forked history).
2. Reconstruct an identical commit object (same tree, parents, author/committer identities and timestamps, message) inside their own attacker-controlled repository, which git will hash to the *same* SHA1.
3. Send a `status` webhook event, correctly signed with their own app's `webhook_secret`, containing that shared `sha` and an arbitrary `state`/`context`/`target_url`/`description` (e.g. `state: success`, forging a CI check).
4. `WebhooksController#verify_signature` validates the signature correctly (it is genuinely signed by the attacker's own org/app).
5. `StatusHandler#process` matches `Commit.where(sha: ...)` against the victim's commit (same sha, different stack/repository) and creates a forged success status on it, with no check that the commit belongs to the attacker's authenticated repository.

### Impact Explanation
This is a cross-repository write: an entity that is only authenticated as owning organization *A* can inject a forged commit status onto a commit belonging to organization *B*'s stack. Since `deployable?` in `Commit` (used to gate deploys) depends on `success?` and blocking-status calculations that are all derived from these `Status` rows, and merge queues are advanced via `stack.schedule_merges` when a status becomes success/pending, a forged "success" status can make an otherwise-non-CI-passing commit appear deployable, or unblock the merge queue, without ever touching the victim's real CI/GitHub org. This matches the "unauthorized deploy" / "cross-repository writes" High/Critical impact classes.

### Likelihood Explanation
Exploitability requires: (a) the attacker be able to install/operate their own legitimate GitHub App on a repository tracked by the same Shipit instance (a normal customer-tenant scenario in multi-org Shipit deployments, as documented for "Using Multiple GitHub Applications"), and (b) the attacker be able to produce a commit with an identical SHA1 to the victim's target commit — feasible when commit metadata (author/committer identities, timestamps, tree) is knowable, e.g. for public open-source repos, forks, or commits authored by the attacker themselves before being merged into the victim repo. This is a moderate-effort but concrete and reproducible attack path, not requiring any privileged Shipit account, API token, or GitHub credential belonging to the victim.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup through the same repository-bound `stacks` helper used by `PushHandler`/`CheckSuiteHandler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or an equivalent query restricted to `Commit.where(stack_id: stacks.select(:id), sha: params.sha)`), so that a `status` event can only ever mutate commits that belong to the same repository it was signed for.

### Proof of Concept
1. Attacker owns/operates GitHub org `attacker-org` with a Shipit-integrated GitHub App (webhook secret `S_attacker`), tracked as a stack in the same Shipit instance that also tracks victim org `victim-org`'s stack.
2. Victim's stack has a commit `C` with sha `abc123...` that is currently `pending`/`failure` (blocking deploy).
3. Attacker crafts a git commit in their own repository with identical tree/parents/author/committer/timestamps/message such that it hashes to `abc123...` (feasible if the commit content is known/public), and pushes it.
4. Attacker sends:
```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, body)>
Body: {
  "sha": "abc123...",
  "state": "success",
  "context": "ci/forged",
  "repository": {"full_name": "attacker-org/attacker-repo", "owner": {"login": "attacker-org"}}
}
```
5. `verify_signature` validates successfully against `attacker-org`'s webhook secret.
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, matches victim commit `C` (different stack entirely), and calls `create_status_from_github!`, creating a forged "success" status on `C` — potentially marking it `deployable?` or advancing the victim's merge queue — without any credential belonging to `victim-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
