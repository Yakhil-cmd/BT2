### Title
`StatusHandler` writes GitHub `status` events to every commit sharing a SHA, regardless of which repository the webhook authenticated for - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no filter on repository/stack, and then writes the incoming state/context to each match via `commit.create_status_from_github!`. Because commit SHAs are not namespaced per repository in this query, and `WebhooksController#verify_signature` only authenticates the request for the organization named in the *attacker's own payload*, an attacker who controls a repository can trigger a `status` webhook for a SHA that a victim stack also happens to track, forcing a `deploy/production` status onto the victim's commit.

### Finding Description
The broken binding: the code implicitly assumes `commit.sha == params.sha` implies `commit.stack.repository == repository_owner/repository_name from the authenticated webhook`. In reality only the former is checked: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` iterates over **all** `Shipit::Commit` rows across **all** stacks/repositories that happen to have that SHA — there is no `stack_id`, `repository_id`, or repo full name filter here or in `Commit`/`Status`: [2](#0-1) [3](#0-2) 

Authentication (`verify_signature`) only proves the request was signed with the webhook secret configured for the *organization named in the attacker's own payload* (`repository.owner.login`), not that the request pertains to any particular victim repository: [4](#0-3) 

So the guard establishes "this request really came from GitHub org X" but never establishes "this request may only affect commits belonging to org X's repositories." `StatusHandler` and `Commit`/`Status` never re-check that binding.

Attack flow:
1. Attacker owns/administers a GitHub repository under an organization/app installation that Shipit is configured to accept webhooks from (this is required merely to pass `verify_signature`; it does not require any Shipit privilege — signature verification is purely about "did GitHub org X sign this", not "is this user authorized in Shipit").
2. Attacker crafts a commit/fork such that a commit with a specific SHA is pushed to their repo, or, more directly, simply sends a forged `status` webhook payload naming `sha: <victim_sha>`, `context: "deploy/production"`, `state: "success"`. SHA collision isn't even required in the classic cryptographic sense — Shipit's `Commit` table just stores 40-hex-char SHAs per stack, and two different stacks/repos can independently have imported/discovered the exact same commit SHA (e.g., shared vendored history, cherry-picks, submodules, monorepo forks, or a victim stack tracking a public open-source SHA that also exists as a commit id string the attacker replays).
3. `WebhooksController#create` dispatches to `StatusHandler`, which fetches `Commit.where(sha: params.sha)` — this hits every commit row in the database with that SHA, including the victim stack's row, and calls `create_status_from_github!` on it.
4. `Status.replicate_from_github!` creates a `Status` record with `state: "success"`, `context: "deploy/production"` attached to the victim's commit and *its own* `stack_id` (taken from `commit.stack_id`, not from the attacker's payload) — so the record lands correctly tied to the victim stack, but the attacker fully controlled its content.
5. `Commit#deployable?` and the `Status::Group` computed in `Commit#status` recompute using this attacker-injected status; if `deploy/production` is a `required` context in the victim's `ci.require` config, this can flip `deployable?` to `true`, unblocking merge/deploy eligibility for a commit the victim never actually got CI success on.

Why existing guards fail: `verify_signature` authenticates "the org that owns the payload's named repository", but `StatusHandler` never compares that org/repo to the repo owning the affected `Commit`/`Stack`. There is no `repository_owner == commit.stack.repository.owner` check anywhere in this path.

### Impact Explanation
This is a cross-tenant integrity violation: a webhook authenticated for repository/org A mutates CI status state for a commit belonging to stack/repository B. If the shared/colliding SHA happens to be a commit the victim considers deployable-gating (`ci.require` includes `deploy/production`), the attacker can force `deployable?` to become true and potentially trigger `ContinuousDeliveryJob`/merge queue advancement for a commit the victim's real CI never approved. This matches "a payload for one repository mutating another's stack, commit, task or team" — Critical per the target's impact classification, assuming a real-world SHA collision or shared-SHA scenario across a victim's and attacker's repositories is achievable (e.g., forked repos with common commit history, or monorepo/submodule setups where the same SHA is tracked by multiple Shipit stacks).

### Likelihood Explanation
- Requires: a GitHub org/repo the attacker controls for which Shipit is configured (so `verify_signature` can succeed) — the attacker needs their own repo to author the webhook, no elevated Shipit privilege.
- Requires: the target SHA to exist as a `Commit` row in the victim stack — this is the main precondition. This is trivially achievable when the victim stack tracks a fork/mirror of the attacker's repository, a shared submodule, or a monorepo where multiple stacks are cut from the same commit history. It is not achievable against an arbitrary unrelated victim with no shared git history, since Shipit only creates `Commit` rows for SHAs it has actually seen via GitHub push/PR events for that stack.
- Attacker cost is a single crafted HTTP POST once the signature can be produced; fully repeatable against any commit SHA the victim stack has recorded, for any status context including ones enumerated in `ci.require`.

### Recommendation
Scope `StatusHandler#process` (and analogous `CheckRunHandler`, `PullRequestHandler`, etc. if they share this pattern) to only touch commits belonging to stacks whose repository matches the authenticated payload's `repository.full_name`/owner — e.g., join through `Stack` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_from_payload.id })` — instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (test/models/webhooks/status_handler_test.rb or similar, no live GitHub):
1. Create two stacks, `victim_stack` (repository `victim/repo`) with `ci.require` containing `"deploy/production"`, and `attacker_stack` (repository `attacker/repo`).
2. Create `victim_commit = victim_stack.commits.create!(sha: SHARED_SHA, ...)` and `attacker_commit = attacker_stack.commits.create!(sha: SHARED_SHA, ...)`.
3. Assert baseline: `assert_not victim_commit.deployable?` (equality check before: `victim_commit.status.state != "success"`).
4. Build a `status` payload: `{ sha: SHARED_SHA, state: "success", context: "deploy/production", repository: { full_name: "attacker/repo", owner: { login: "attacker" } } }` and call `Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)` (bypassing controller-level signature check, focusing purely on handler logic per the target).
5. Reload `victim_commit`; assert `victim_commit.status.state == "success"` and `victim_commit.deployable? == true` — demonstrating the equality `commit.stack.repository == authenticated_repository` was never enforced, and the victim's status/deployability changed from an event authenticated only for `attacker/repo`.

### Citations

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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
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
