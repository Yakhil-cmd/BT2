This confirms the finding: `CheckSuiteHandler#process` correctly scopes to `stacks.where(branch: ...)` derived from the payload before touching commits, and `PushHandler#process` scopes via `stacks.not_archived.where(branch:)`. By contrast `StatusHandler#process` does `Commit.where(sha: params.sha)` with **no** stack/repository scoping at all [1](#0-0) , unlike its sibling handlers [2](#0-1) [3](#0-2) .

### Title
Cross-repository commit-status forgery via unscoped `sha` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` applies an incoming GitHub `status` webhook to every `Commit` row that shares the reported `sha`, regardless of which repository/stack the webhook actually originated from. Because git commit shas are content-addressed and reproducible by anyone who knows a commit's tree/parent/author/committer/message, an attacker who controls any repository within a GitHub organization already onboarded to this Shipit instance can reproduce the exact bytes of a "blocked" commit that also exists in a victim stack, get their own CI to mark that sha "success," and have the resulting (validly-signed) webhook poison the unrelated victim commit's status.

### Finding Description
The equality the system should enforce but does not: `payload.repository.full_name == commit.stack.repository.full_name` (the CI/status event must be scoped to the exact repository that owns the target commit). Instead, `StatusHandler#process` only checks sha equality: [1](#0-0) 

`Commit.where(sha: params.sha)` performs a *global* lookup across the entire `commits` table — every stack, every repository, every organization — with no filter on `stack_id` or on the payload's `repository` field. For each match it calls `commit.create_status_from_github!(params)`, which writes the forged status into that commit's *own* `stack_id`: [4](#0-3) 

The only gate before this handler runs is `WebhooksController#verify_signature`, which authenticates the webhook against the GitHub organization derived from `params.dig('repository','owner','login')` — it authenticates the *sender's organization*, not the specific target repository/stack that the sha belongs to: [5](#0-4) 

Exploit flow:
1. Attacker has push access to (or owns) some repository within a GitHub organization that Shipit already has a GitHub App/webhook configured for (any repo in that org, not necessarily the victim's).
2. Attacker observes a "blocked" commit on the victim stack (e.g. a PR with failing/pending CI, sha `X`) — all metadata (tree, parent, author, committer, timestamps, message) is public.
3. Attacker recreates a byte-identical commit object (same sha `X`) in their own repository (trivial, since git commits are content-addressed and no collision is needed — it's the literal same object, e.g. via a fork or manually rebuilding the commit with `git commit-tree`).
4. Attacker's own CI (fully under their control) posts a `success` status for sha `X` against their own repository via the GitHub Status API.
5. GitHub signs and delivers the resulting `status` webhook to Shipit using the organization's real `webhook_secret` — signature verification passes because it only checks the org, not the specific repository tied to the commit.
6. `StatusHandler#process` finds the victim's `Commit` row (same sha) via the unscoped `Commit.where(sha: params.sha)` query and calls `create_status_from_github!`, writing a `Status(state: 'success', stack_id: victim_stack.id)` — this happens even though CI never ran in the victim's own repo/CI provider context.
7. `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) now evaluates `success?` true using the forged status [6](#0-5) .
8. `Stack#next_expected_commit_to_deploy`/`next_commit_to_deploy` then selects this commit [7](#0-6) , and with `continuous_deployment: true`, `trigger_continuous_delivery` ships it [8](#0-7) .

No existing guard catches this: `verify_signature` only checks the organization-level HMAC, not repository identity; `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of the payload (`sha`, `state`, etc.), not repository ownership; there is no model validation tying a `Status` write to the repository that the webhook actually came from.

### Impact Explanation
This is a payload for one repository mutating another stack's commit record — matching the "Critical" category explicitly listed in scope ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). With `continuous_deployment: true`, this directly causes an unauthorized deploy of attacker-influenced/attacker-chosen code that never passed the victim repository's actual CI. The blast radius spans every stack/repository whose Shipit instance shares an organization-level (or, since the query has zero scoping, even cross-organization) GitHub App installation — any stack tracked by the same Shipit deployment is vulnerable, not just one.

### Likelihood Explanation
Preconditions: victim stack has `continuous_deployment: true` and an existing "blocked"/pending commit whose full metadata is publicly visible (typical for an open PR). The attacker needs only ordinary contributor/collaborator access to some repository inside a GitHub organization already onboarded to Shipit (per `docs/setup.md`, orgs are configured with their own `webhook_secret`) — this is consistent with "unprivileged" per the rules (able to push to a repo they own/control and receive/emit GitHub webhooks from it). No Shipit credentials, GitHub App keys, or `webhook_secret` knowledge are required, since GitHub itself computes and attaches the valid signature for the attacker's own repository. Reproducing a byte-identical commit object for the target sha is a standard git operation (no SHA1 collision needed), making this highly feasible and repeatable against any tracked repository/stack.

### Recommendation
Scope `StatusHandler#process` to the stack(s)/repository actually identified by the webhook payload, mirroring `PushHandler`/`CheckSuiteHandler`. Resolve the repository from `params.dig('repository','full_name')` (or the branches in the payload) to the specific `Stack`/`Repository`, then constrain the commit lookup to `stack.commits.where(sha: params.sha)` instead of `Commit.where(sha: params.sha)` across the whole table.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks/repositories in fixtures: `victim_stack` (continuous_deployment: true) with a blocked commit `commit_v` (sha `S`, pending/no successful status), and `attacker_stack` belonging to a *different* repository but same GitHub organization.
2. Also create a `Commit` row under `attacker_stack` with the same sha `S` (simulating the byte-identical commit reproduced by the attacker), with no relation to `commit_v` other than the sha.
3. Assert baseline: `assert_nil victim_stack.next_expected_commit_to_deploy` (or assert commit_v is excluded) since `commit_v.deployable?` is false.
4. POST a `status` webhook payload with `sha: S`, `state: 'success'`, and `repository.full_name` set to the *attacker's* repository (stub/allow `verify_signature` to pass, as done in existing tests via `GithubHook.any_instance.stubs(:verify_signature).returns(true)`), driving `StatusHandler#process` directly or via the controller.
5. Reload `commit_v` and assert `commit_v.success?` is now true and `commit_v.deployable?` is true, even though the status came from the attacker's repository payload.
6. Assert `victim_stack.next_expected_commit_to_deploy` now returns `commit_v`, proving the poisoned commit becomes selected for deploy despite no CI having run against the victim repository/CI provider — the equality `payload.repository.full_name == commit_v.stack.repository.full_name` is false, yet the deploy pipeline treats it as true.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
