### Title
Cross-tenant Commit status mutation via unscoped `Commit.where(sha:)` in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone, with no repository/stack scoping, and calls `create_status_from_github!` on every match. If the same `sha` exists on N different `Stack`/`Repository` records (e.g., forked/template repos sharing an initial commit), one signed webhook from any single one of those repositories mutates the `Status` rows of all N commits, not just the one belonging to the repository that authenticated the request.

### Finding Description
The claimed binding is: `mutated_stacks_count == 1` (only the `Stack`/`Repository` named in `payload['repository']['full_name']`). The actual code produces `mutated_stacks_count == N`, where N is however many `Commit` rows across the entire `commits` table happen to share `params.sha`: [1](#0-0) 

Contrast this with the base `Handler` class, which defines a `stacks` helper that *does* scope by `repository_name` derived from `payload.dig('repository', 'full_name')`: [2](#0-1) 

`StatusHandler` never calls this `stacks` helper — it queries `Commit` globally by `sha` only. `Commit#create_status_from_github!` then calls `add_status`, which appends a `Status` record and re-evaluates the commit's status, emitting `Hook.emit(:commit_status, ...)` and potentially scheduling merges/continuous delivery for the *other* stacks' commits: [3](#0-2) [4](#0-3) 

Webhook signature verification (`verify_signature`/HMAC check in `WebhooksController`) only proves the payload was signed by *some* registered GitHub App/webhook secret for *the repository that sent it* — it says nothing about which `Commit` rows should be affected. Since `sha` is a value fully controlled by whoever pushes commits to their own repository (an unprivileged attacker can create a repo, e.g. from a shared template, with an identical initial commit sha to an existing target stack, or intentionally craft/rebase a commit to collide), the attacker can trigger writes to `Commit`/`Status` rows belonging to stacks/repositories they neither own nor authenticated for. This is a real fan-out: any N≥2 stacks that happen to share a sha are all affected by one request from any one of them — the guard rails (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) validate the payload shape and signature but never scope the mutation to the authenticated repository.

### Impact Explanation
A single signed webhook from an attacker-controlled repository writes `Status` rows (build/CI state) onto `Commit` records belonging to unrelated stacks/repositories that share the same commit sha. This can flip a target stack's commit into "success"/"pending" state, which feeds `deployable?`, `blocked?`, and `schedule_continuous_delivery`, potentially unblocking or triggering deploys on a repository the attacker never authenticated against — this is a payload for one repository mutating another's stack/commit and can influence unauthorized deploy behavior in the target stack, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). Blast radius scales with however many independent Stack/Repository records happen to share the sha (N≥2, N≥3 as posed), which is entirely outside the attacker's control or access — they only need to know or engineer a matching sha and control one webhook-emitting repository.

### Likelihood Explanation
Preconditions: at least one other legitimate `Commit` row somewhere in the installation shares the exact 40-char sha with a commit the attacker can produce in their own repository. Real-world collision requires either (a) template/fork-derived repositories that share an initial commit (common with scaffolding tools, monorepo templates, or copied history) or (b) deliberate git history construction to reuse a sha across independently-registered repos (feasible since git allows importing/rewriting history to match an arbitrary existing commit if the attacker knows it, e.g. by observing a public repo's initial commit and replicating it). No Shipit secrets, sessions, or GitHub App keys are needed — only a repository the attacker owns and a legitimate webhook signed with that repository's own webhook secret (standard GitHub setup for any registered repo). This is fully repeatable: every commit-sha collision the attacker arranges results in cross-tenant writes on every subsequent status webhook they send.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository/stack that authenticated the webhook, using the same `stacks` helper the base `Handler` class already provides, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so only commits belonging to the sending repository's own stacks are updated.

### Proof of Concept
Minitest plan (under `test/models/shipit/webhooks/handlers/status_handler_test.rb`, not included here per scope but described):
1. Create 3 `Stack`/`Repository` fixtures (`repo_a`, `repo_b`, `repo_c`) with distinct `github_repo_name`s.
2. Create a `Commit` under each stack with the identical `sha = "deadbeef" * 5` (40 chars).
3. Build a signed webhook payload for `repo_a` only (`repository.full_name = repo_a.github_repo_name`), with `state: "success"`.
4. POST to `/webhooks` with a valid `X-Hub-Signature`/`X-Hub-Signature-256` for `repo_a`'s registered secret.
5. Assert: `commit_a.statuses.count` increased by 1 (expected, intended target).
6. Assert (demonstrating the bug): `commit_b.statuses.count` and `commit_c.statuses.count` also increased by 1, even though the webhook only authenticated for `repo_a`. Under the claimed binding (`mutated_stacks_count == 1`), these should remain 0; the current code makes them equal 1 as well, proving N>2 fan-out.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

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
