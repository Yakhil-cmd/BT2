### Title
Cross-repository `Commit` status mutation via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike every other webhook handler which resolves `stacks` via `Repository.from_github_repo_name(repository_name)`. This lets a validly-signed `status` event for one repository silently rewrite the CI status of a commit belonging to a completely different stack whenever the two repositories happen to share a commit SHA (forks, template repos, monorepo splits, repo migrations/renames).

### Finding Description
The invariant claimed is: `commit.stack.repository == webhook.payload.repository` for every `Status` record created by a `status` event. This does not hold.

`Handler` (the shared base class) exposes a `stacks` helper that scopes lookups to the authenticating repository: [1](#0-0) 

`StatusHandler#process`, however, never calls `stacks` or filters by `repository_name`; it queries `Commit` globally by SHA alone: [2](#0-1) 

`Commit.where(sha: params.sha)` is not scoped by `stack_id` or any repository identifier, so any commit row in any stack, belonging to any repository/organization, whose `sha` matches the attacker-influenced value is updated via `commit.create_status_from_github!(params)`, which writes a `Status` and can flip `deployable_status`/`commit_status` state and schedule continuous delivery: [3](#0-2) [4](#0-3) 

**Root cause**: `StatusHandler` diverges from the pattern used by `PushHandler`/`PullRequest::*Handler` (which restrict all writes to `stacks` derived from `payload.dig('repository', 'full_name')`); it trusts a bare SHA as if it were globally unique to one repository, which is false whenever repositories share commit history (forks, template-generated repos, repo splits/renames).

**Guard analysis**:
- `verify_signature` in `Shipit::WebhooksController` validates the HMAC signature using `Shipit.github(organization: repository_owner)`, which is scoped to the **GitHub organization**, not the individual repository: [5](#0-4) . This blocks a fully external, unauthenticated attacker who has no relationship to any Shipit-configured organization — they cannot forge a valid signature.
- It does **not** block an attacker who has legitimate CI/push access to a *different* repository within the same GitHub organization/App installation as the victim stack (a realistic scenario since GitHub Apps/webhook secrets are typically installed at the org level, covering all member repos). Such an attacker can cause GitHub to relay a validly-signed `status` payload for their own repository/CI job, with `context: continuous-integration/travis-ci`, `state: failure`, and a SHA that coincides with a commit that also exists (identical SHA) in the victim's stack due to shared commit history (fork, template repo, monorepo split, or a repository that was renamed/re-onboarded as a new `Stack`).
- No other guard (`drop_unhandled_event`, `ExplicitParameters` schema, model validations) checks that the SHA belongs to the authenticating repository; the params schema only validates types/presence, not repository ownership.

**Exploit flow**: attacker with push/CI access to Repo B (same org as victim Repo A/Stack) causes a `status` webhook with `sha` = a commit shared with Repo A, `context: continuous-integration/travis-ci`, `state: failure` to be delivered. `StatusHandler#process` updates every `Commit` row across the DB with that SHA, including the one belonging to Stack A, flipping its CI status and potentially blocking/unblocking auto-merge or continuous deployment for Stack A regardless of what Repo A's real CI reported.

### Impact Explanation
A payload authenticated only for one repository mutates a `Commit`/`Status` belonging to a stack tied to a *different* repository, matching the explicitly in-scope Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius is every stack across every organization sharing the compromised GitHub App/org secret whose commit history overlaps (forks, templates, renamed/migrated repos) with the attacker's repository. Repeated for each shared SHA, this can be used to force `deployable_status`/`commit_status` transitions that block legitimate deploys or (per `Commit#schedule_continuous_delivery`) contribute to unwanted continuous-delivery scheduling on a victim stack.

### Likelihood Explanation
Requires the attacker to control a repository (or CI integration posting statuses) within the same GitHub organization/App installation as the victim stack — this is a real but non-trivial precondition; a fully external, unrelated attacker is blocked by `verify_signature`'s org-scoped signature check. It further requires a SHA collision, which in practice means shared git history (forks, template-cloned repos, monorepo splits, or repository renames re-registered as new stacks) rather than a cryptographic SHA1 preimage break. Given these preconditions, the attack is cheap and repeatable (one webhook per exploitation), and the underlying code defect (missing repository scoping) is unconditional.

### Recommendation
Scope `StatusHandler#process` the same way as other handlers: resolve `stacks` from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`, and only update `Commit` rows belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (no live GitHub):
1. Create two `Repository`/`Stack` fixtures, `repo_a` (victim) and `repo_b` (attacker-controlled), both under the same `github_teams`/org signature scope.
2. Create a `Commit` with an identical `sha` in both `repo_a.stack.commits` and `repo_b.stack.commits` (simulating shared history).
3. Stub `GithubHook#verify_signature` to return true (as in `test/controllers/webhooks_controller_test.rb`).
4. POST to `/webhooks` with `X-Github-Event: status`, body `{ sha:, state: 'failure', context: 'continuous-integration/travis-ci', repository: { full_name: repo_b.full_name, ... } }`.
5. Assert: `commit_a.reload.status.state == 'failure'` even though the payload's `repository.full_name == repo_b.full_name`, proving `commit.stack.repository != payload.repository` — the broken binding.
6. Compare against expected behavior: assert instead `commit_a.reload.status.state` is unchanged (still its prior state) once the fix scopes the lookup to `repo_b`'s stacks only.

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
