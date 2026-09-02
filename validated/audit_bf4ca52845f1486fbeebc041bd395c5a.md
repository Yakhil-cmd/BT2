This confirms the vulnerability: other handlers (e.g. `PullRequest::OpenedHandler`) use the `Handler` base class's `stacks`/`repository_name` helpers, which scope lookups via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`. `StatusHandler`, however, never uses `payload['repository']` at all — its `params` schema doesn't even require a `repository` field, and `process` queries `Commit.where(sha: params.sha)` globally, then calls `commit.create_status_from_github!(params)` for every match, regardless of which repository/stack the commit belongs to.

`verify_signature` in `Shipit::WebhooksController` only proves the payload was signed by the GitHub App/webhook secret configured for `repository_owner` (the org that produced it) — it says nothing about whether the `sha` inside the payload actually belongs to that repository. Since Git SHAs are content-addressed (tree + parents + commit metadata), any attacker who controls a repository can produce a commit whose SHA equals a SHA already present in an unrelated tenant's `stack` (e.g., via cherry-pick, empty-tree replay, or identical commit metadata). A legitimate CI job on the attacker's own commit then causes GitHub to send a validly-signed `status` webhook for that SHA. `StatusHandler#process` will match and mutate every `Commit` row across every repository/stack sharing that SHA.

### Title
Unscoped `status` webhook write via bare-SHA lookup poisons CI state across repositories - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike sibling handlers that scope through `Repository.from_github_repo_name(payload['repository']['full_name'])`. A validly-signed `status` webhook from an attacker-controlled repository containing a SHA that collides with a commit in another tenant's stack will overwrite that commit's CI status and deployability everywhere the SHA appears.

### Finding Description
The broken invariant: `commit.stack.github_repo_name == payload['repository']['full_name']` should hold for every commit updated by a `status` event, but `StatusHandler` never reads or checks `payload['repository']` at all — its `params` schema (`app/models/shipit/webhooks/handlers/status_handler.rb:7-18`) only requires `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`. `process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

`Commit` has no repository column of its own; it only relates through `belongs_to :stack`, and `stack.github_repo_name` is what associates it to a repo. `Commit.where(sha:)` is unscoped SQL across the whole `commits` table. `create_status_from_github!` calls `add_status`, which updates `statuses`, recomputes `status`, and can flip `deployable?`, trigger `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges` — real state mutation, not just a display artifact [2](#0-1) [3](#0-2) .

Contrast with `Handler#stacks`, used by other handlers, which resolves via the payload's own `repository.full_name`: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none` [4](#0-3) . `StatusHandler` bypasses this entirely.

`WebhooksController#verify_signature` only authenticates that the payload came from the GitHub App/org matching `repository_owner` in the payload — it validates *who sent* the webhook, not that the `sha` inside legitimately belongs to that sender's repository [5](#0-4) . Since Git commit SHAs are derived purely from tree/parents/metadata content, an attacker who owns any GitHub repository can reproduce an identical SHA to a target's commit (cherry-pick, empty-tree commit, or replaying the same tree+parent+author/committer info) and get a valid signed `status` event for it from their own CI/repo, with no privilege in the target's Shipit instance or GitHub org required.

### Impact Explanation
Any repository onboarded to the same Shipit instance (which need not even be privileged relative to the target) can, via ordinary CI activity on a colliding SHA, overwrite CI status/description/target_url and flip `deployable?` for a commit belonging to a completely different tenant's stack, potentially unblocking or blocking a deploy pipeline it doesn't own. This is a cross-tenant write: a payload signed for repository A's org mutates repository B's `Commit`/`Status` rows and `stack.deployable?` decision. This matches "Critical — a payload for one repository mutating another's stack, commit, task, or team." The attack is repeatable against any known/reproducible SHA collision and scales to every stack sharing that SHA, not just one.

### Likelihood Explanation
Preconditions: attacker needs their own onboarded (or any) GitHub repository whose webhook events reach the shared Shipit instance, and the ability to construct a commit with an identical SHA to a target commit (achievable deterministically via cherry-pick/empty-commit replay when tree, parent, message, author/committer date all match — a known, low-cost technique, not a hash break). No Shipit credentials, GitHub team membership, or target-repo access is required. The webhook signature check only validates the sender's own org's secret, which the attacker legitimately possesses for their own repo's app installation context. This is feasible and repeatable at will.

### Recommendation
Scope `StatusHandler#process` by the reporting repository: require `repository.full_name` in the `params` schema (as other handlers do), resolve the target repository/stacks via `Repository.from_github_repo_name`, and restrict the `Commit` lookup to `commit.stack.github_repo_name == repository_name` (e.g., join/scope commits through that repository's stacks) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create `repo_a` and `repo_b` as separate `Shipit::Repository` records, each with a `Stack`.
2. Create a `Commit` with `sha: "deadbeef...".ljust(40,'a')` under `stack_a` (repo_a) and another `Commit` with the *same* sha under `stack_b` (repo_b), simulating the cherry-picked/empty-tree collision.
3. Build a `status` webhook payload with that `sha`, `state: "success"`, and `repository.full_name` set to `repo_a`'s name only (as GitHub would send for repo_a's event).
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `commit_a.reload.state == "success"` (expected) AND `commit_b.reload.state == "success"` / `commit_b.deployable?` changed — proving the payload signed/produced for repo_a mutated repo_b's commit, with equality `commit_b.stack.github_repo_name == payload['repository']['full_name']` being false yet the write still occurring.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
