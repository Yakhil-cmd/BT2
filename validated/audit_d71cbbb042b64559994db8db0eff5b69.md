### Title
Webhook status handler updates commits across all stacks by SHA alone, with no binding to the authenticating repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` (`Commit.where(sha: params.sha)`) with no scoping to the repository/organization that authenticated the inbound webhook. Any Shipit-registered repository can therefore push a genuinely-signed status webhook (using its own credentials, for its own commit history) that updates the status of an identically-shaed commit belonging to an unrelated Victim stack, because Git commit SHAs are content-addressed and identical across forks/mirrors of the same history.

### Finding Description
The claimed binding is:

`MergeRequest#stack` (Victim stack whose merge gets scheduled) == `Stack` owning the `repository_owner` that passed `verify_signature`

Tracing the code shows this equality is never enforced:

- `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) authenticates the webhook only against `Shipit.github(organization: repository_owner)`'s `webhook_secret` — i.e., it proves the payload came from *some* org/app registered in Shipit, not that it belongs to any particular stack or commit. [1](#0-0) 

- `StatusHandler#process` then resolves target commits **purely by SHA**, with no filter on repository, stack, or the `repository_owner`/`repository.full_name` that was just authenticated: [2](#0-1) 

- `Commit#create_status_from_github!` → `add_status` then unconditionally records the new status and calls `stack.schedule_merges` when the new state is `pending?` or `success?` — `stack` here is the commit's own `belongs_to :stack`, i.e. whatever stack that Commit row happens to belong to, not the stack tied to the webhook's repository: [3](#0-2) [4](#0-3) 

Root cause: Git commit SHAs are content-addressed hashes of a commit's tree/parents/message/author, not repository-scoped identifiers. Any fork, mirror, or independently-onboarded Shipit stack that shares history with the Victim repository (a common situation for public/open-source projects, monorepo forks, or multiple Shipit stacks tracking the same upstream) will contain `Commit` rows with identical `sha` values across different `stack_id`s. Because `StatusHandler` never joins/filters by `stack.repository` (or `params.dig('repository','full_name')`), a status update legitimately delivered for the attacker's own repository is fanned out to *every* `Commit` row sharing that SHA, including the Victim's.

Attacker's exact path:
1. Attacker owns (or forks) a public repository whose commit history overlaps with the Victim's repository, and onboards their own copy as a Shipit stack under their own GitHub org/app config (their own `webhook_secret`, held by GitHub/Shipit, never by the attacker — but the attacker doesn't need it: GitHub computes and sends the valid signature for events on the attacker's own repo).
2. Attacker sets a `state=success` commit status via the GitHub API on a commit SHA in their own repository that is identical to the head SHA of a pending `MergeRequest` in the Victim's stack.
3. GitHub delivers a genuinely-signed `status` webhook to `POST /webhooks`; `verify_signature` passes because it's validly signed for the attacker's own org.
4. `StatusHandler#process` finds **all** `Commit` rows with that `sha`, including the Victim's, and calls `create_status_from_github!` on each — including the Victim's commit, whose `stack` is the Victim stack.
5. `Commit#add_status` records the forged success status on the Victim's commit and calls `stack.schedule_merges` (Victim stack), since `new_status.success?`.
6. The asynchronous merge job evaluates `all_status_checks_passed?` off the now-poisoned local `statuses`/`status` cache (not a live GitHub re-check), and proceeds to merge/queue the Victim's `MergeRequest` despite the Victim's real CI never reporting success.

None of the existing guards prevent this: `verify_signature` authenticates the *sender org*, not the *target commit's owner*; `drop_unhandled_event` only filters event types; the `ExplicitParameters` schema on `StatusHandler` only validates payload shape (`sha`, `state`, etc.), not repository binding; there is no `Repository`/`full_name` check anywhere between webhook ingestion and the `Commit.where(sha:)` lookup.

### Impact Explanation
A payload authenticated for one repository/organization mutates state (`Status` rows) belonging to another, unrelated stack's commit, and that mutation is then consumed by `Stack#schedule_merges` to drive an unauthorized merge decision. This is a cross-tenant integrity break: an attacker controlling any Shipit-registered repository (even a low-value or throwaway one) can cause a queued merge on a completely different, higher-value stack whose real CI never passed. This matches "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge" (Critical). It is repeatable against any Victim stack/commit that shares a SHA with a repository the attacker controls, which is realistic for any project with forks, mirrors, or multiple Shipit-tracked copies of the same history.

### Likelihood Explanation
Preconditions: (1) attacker must have (or be able to onboard) a Shipit-registered repository under some organization configured in the Shipit instance (a normal, low-privilege action for open, self-serve Shipit deployments, or trivially true if the attacker forks and the fork is also tracked); (2) a commit with an identical SHA must exist in both the attacker's repo history and the Victim's stack (guaranteed for any unmodified shared commit, e.g., common base commits, cherry-picks, or forks that haven't diverged at that point); (3) Victim stack must have `merge_queue_enabled?` and a pending `MergeRequest` on that commit, as stated in preconditions. Attacker cost is low: standard GitHub API calls against their own repository, no secrets required, fully repeatable.

### Recommendation
Scope `StatusHandler#process` (and equivalent check-run/other webhook handlers) to only update commits belonging to the stack(s) whose repository matches the webhook's authenticated `repository.full_name`/`repository_owner`, e.g. filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_from_payload.id })` instead of an unscoped SHA lookup, ensuring the binding "commit's stack repository == authenticated webhook repository" is enforced before any status is written or `schedule_merges` is invoked.

### Proof of Concept
Minitest plan (no live GitHub, uses existing webhook/test helpers):
1. Create two `Repository`/`Stack` fixtures: `victim_stack` (owner `victim-org/app`) and `attacker_stack` (owner `attacker-org/app-mirror`), each with distinct `github_app`/webhook secret config in test secrets.
2. Create a `Commit` with `sha: "deadbeef...".ljust(40,'a')` under `victim_stack`, and a `MergeRequest` on `victim_stack` referencing that commit as its head, with `victim_stack.update!(merge_queue_enabled: true)`.
3. Create a second `Commit` with the **same sha** under `attacker_stack` (simulating shared history).
4. POST to `/webhooks` a `status` event payload with `repository.owner.login = "attacker-org"`, `sha` = the shared sha, `state = "success"`, signed with `attacker-org`'s configured `webhook_secret` (i.e., an entirely valid signature for the attacker's own org).
5. Assert the request returns 200 and that `victim_stack`'s `Commit` (looked up by id, not sha) now has `status.success?` true, and that `Stack#schedule_merges` was invoked/enqueued for `victim_stack` — i.e.:
   `assert_equal true, Commit.find(victim_commit.id).success?` while asserting no request/credential ever referenced `victim-org` or `victim_stack`'s webhook secret.
6. Run the merge-request processing job and assert the `MergeRequest` on `victim_stack` transitions toward `merge_queue`/`merged` state, demonstrating the queued merge occurred without any genuine status from `victim-org`'s own CI.

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
