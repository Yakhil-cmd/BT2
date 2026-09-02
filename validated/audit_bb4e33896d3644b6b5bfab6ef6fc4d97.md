### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook validated for one repository mutate commit status/deployability in any other stack sharing that SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)` with no repository/stack scoping, while `WebhooksController#verify_signature` only authenticates that the payload came from a known GitHub *organization* (`repository_owner`), never that it belongs to the specific repository owning the commit being mutated. Because git SHAs are content-addressed and identical across forks of the same repo, a commit that is simultaneously tracked as a review-stack commit in the "upstream" stack and as a normal commit in an attacker-controlled fork can have its `shipit/checks` status flipped by a webhook authenticated only for the fork.

### Finding Description
The broken invariant, stated as an equality that should hold but doesn't:
`commit.stack_id == webhook_authenticated_repository.stack_id` for every `Commit` updated by a `status` event — but `StatusHandler` never enforces this.

Code path:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, which authenticates the *organization* the payload claims to be from, not the specific repository that owns the target commit: [1](#0-0) 
2. `StatusHandler#process` then does a global, repository-agnostic lookup and applies the status to every matching row: [2](#0-1) 
3. `Commit#create_status_from_github!` → `add_status` recomputes `status`/`deployable?` and, on state change, calls `stack.schedule_merges` and emits `deployable_status`/`commit_status` hooks, directly affecting deploy/merge decisions for whichever stack owns that commit row: [3](#0-2) [4](#0-3) 

Root cause: git commit SHAs are content-addressed, so the identical SHA can legitimately exist in two different `Commit` rows belonging to two different `Stack`s — most commonly the upstream repo (whose review stack, auto-provisioned because `review_stacks_enabled` + `allow_all`, tracks the PR head SHA) and the contributor's own fork (which contains the byte-identical commit object). If the attacker's fork is covered by the same GitHub App/webhook installation and secret that Shipit trusts for the organization (a realistic setup, since `review_stacks_enabled`+`allow_all` exists precisely to auto-onboard external-fork PRs), the attacker can legitimately call GitHub's Status API on their own fork/commit (`context: shipit/checks`, `state: failure`) and have GitHub deliver a validly-signed webhook. `StatusHandler` then updates the *upstream* review-stack's `Commit` row sharing that SHA, without the upstream repository ever having authenticated that specific status.

Existing guards don't stop this: `verify_signature` validates org-level HMAC only, not repository identity; `ExplicitParameters` schema only validates payload shape (`sha`, `state`, `context` types), not ownership; there is no `repository`/`stack_id` filter anywhere in `StatusHandler#process`.

### Impact Explanation
A status payload authenticated for one repository can flip `deployable?`/`blocked?` state and trigger merge/deploy scheduling (`stack.schedule_merges`) for a commit belonging to a *different* stack — i.e., "a payload for one repository mutating another's stack/commit," which forces or blocks a ship decision for a review stack the attacker never authenticated against. Because review stacks execute `shipit.yml`, forcing deployability can lead to unauthorized task/command execution on the deploy host for that stack. This is repeatable against any stack that shares a SHA with an attacker-reachable repository (most naturally via fork-based PR workflows), and the blast radius spans any tenant/stack whose commit table happens to intersect on SHA with an attacker-controlled repo under the same trusted GitHub App installation.

### Likelihood Explanation
Preconditions: victim stack has `review_stacks_enabled: true, allow_all: true` (so external-fork PRs auto-provision review stacks and run `shipit.yml`), and the attacker's own fork/repo is covered by the same GitHub App installation/webhook secret Shipit trusts for that organization. Given that precondition, attacker cost is low — they only need to open a PR (creating the shared-SHA commit) and then call the standard GitHub Status API against their own fork's copy of that same commit, which requires no Shipit credentials at all.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and equivalently in `CheckRunHandler`/other SHA-keyed handlers) to the repository that authenticated the webhook, e.g. join through `Stack.where(repository: repo_from_payload)` before matching by `sha`, rejecting/ignoring statuses whose payload repository does not match the commit's owning stack's repository.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_a` (repository `upstream/repo`) with `required_status: 'shipit/checks'`.
2. Create `stack_b` (repository `attacker/fork`), unrelated tenant/org.
3. Create two `Commit` rows with the **same** `sha` — one under `stack_a`, one under `stack_b` — mirroring a shared fork commit.
4. Build a `status` webhook payload with `sha` equal to that shared SHA, `context: 'shipit/checks'`, `state: 'failure'`, and a `repository` block identifying `attacker/fork` (i.e., only authenticated for `stack_b`).
5. Call `StatusHandler.new.call(payload)` (or process through the controller with a signature valid for `attacker`'s org).
6. Assert: before processing, `stack_a`'s commit `deployable?` == `true`/whatever baseline; after processing, `stack_a`'s commit `deployable?` flips to `false` (or `blocked?` becomes `true`) even though no webhook was ever authenticated for `upstream/repo` — proving cross-repository mutation of `stack_a` from a payload scoped to `stack_b`.

### Citations

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
