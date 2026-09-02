### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a webhook for one repository forge deploy-gating status on another repository's commit, with no defense-in-depth in `Stack#trigger_continuous_delivery` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/stack.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire database, `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }`, without checking that `params`'s `repository.full_name` matches the repository owning the matched `Commit`. `Stack#should_resume_continuous_delivery?` and `Stack#should_delay_continuous_delivery?`, consulted from `trigger_continuous_delivery`, only inspect `Stack`/`Commit` state (`deployable?`, `deployed_too_recently?`, `checks?`, `deployment_checks_passed?`, `commit.recently_pushed?`) and never re-validate that the `Commit#status` backing that state came from a webhook verified against `stack.repository`.

### Finding Description
The claimed binding is: `Commit#status(sha).origin_repository == stack.repository`. Tracing the code shows this is never asserted anywhere in the path.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) only checks that the HMAC signature is valid for the organization named in `payload['repository']['owner']['login']`. It authenticates *that the sender knows the secret for that org's GitHub App*, not that the `sha` inside the payload belongs to that org's repository. [1](#0-0) 
- `StatusHandler#process` then resolves commits **by SHA only**, with no repository filter at all: [2](#0-1) 
  This is inconsistent with the base `Handler#stacks` helper, which does scope by `repository_name` for other handlers, showing the repo-scoping is expected but simply omitted here. [3](#0-2) 
- Downstream, `Stack#trigger_continuous_delivery` selects a commit via `next_commit_to_deploy` (which relies on `Commit#deployable?`, itself driven by `Commit#status`/`Commit#state`) and gates it only through `should_resume_continuous_delivery?` and `should_delay_continuous_delivery?`: [4](#0-3) [5](#0-4) 
  None of these predicates reference webhook provenance, `params`, `payload`, or `repository.full_name` — they are pure functions of `Stack` columns (`continuous_delivery_delayed_since`, `continuous_deployment`, `locked_since`, etc.) and `Commit` status/state that was already written by the unscoped handler. There is no point in this chain that re-derives "was this status authored for *this* repository."

Exploit flow: an attacker who has push/API access to any repository sharing commit history with a victim's monitored repository (most straightforwardly, an org-internal fork of a repo already covered by the org's installed GitHub App, which preserves identical commit SHAs) creates a commit status (e.g. `state: success`, matching `required_statuses`) via the GitHub API on their own fork. GitHub signs and delivers this webhook legitimately (the attacker never needs `webhook_secret` or `api_clients_secret`); `verify_signature` passes because the signature is valid for the org. `StatusHandler#process` then attaches that status to **every** `Commit` row sharing that SHA, including the one tracked by the victim stack, because the lookup has no repository filter. The victim's `Commit#deployable?`/status is now forged. `Stack#trigger_continuous_delivery` (or a manual/API deploy trigger) subsequently treats the forged commit as passing, and since `should_resume_continuous_delivery?`/`should_delay_continuous_delivery?` never look at status provenance, nothing blocks `trigger_deploy`.

### Impact Explanation
A payload delivered for one repository (the attacker's fork/own repo) is used to mutate commit/status state and ultimately gate `Task`/`Deploy` creation for a different repository's `Stack`, resulting in an unauthorized deploy trigger — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." Blast radius spans any two repositories in the multi-tenant Shipit install that ever share a commit SHA (forks, mirrors, repo renames/transfers), and is repeatable per SHA/status-context combination.

### Likelihood Explanation
Requires: (1) a Shipit instance monitoring a repository whose commit history is duplicated in a second repository the attacker can write commit-statuses on (e.g., an org-scoped GitHub App installation covering "all repositories" including attacker-creatable forks), and (2) the victim stack's deploy spec's `required_statuses`/checks to be satisfiable by a forged `success` status. No Shipit secrets are needed — only ordinary GitHub write access to a covered repository, which is consistent with the stated unprivileged-attacker capabilities (push to a repo/fork they control).

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository named in the webhook payload (e.g., filter through `stacks`/`Repository.from_github_repo_name(payload.dig('repository','full_name')).commits.where(sha: params.sha)`) instead of matching by SHA globally, mirroring the pattern already used by `Handler#stacks`.

### Proof of Concept
Minitest plan (`test/webhooks/status_handler_test.rb`-style, no live GitHub):
1. Create `repository_a` with `stack_a`, and `repository_b` with `stack_b`; create a `Commit` with the same `sha` under both stacks (simulating a shared/forked commit).
2. Build a status webhook payload with `repository.full_name = repository_a.github_repo_name` and `sha` equal to the shared SHA, `state: 'success'`, context matching `stack_b`'s `required_statuses`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, which is out of scope here since the point is the missing repo-scope in `process`).
4. Assert `stack_b.commits.find_by(sha: sha).status.simple_state == 'success'` even though the webhook's `repository.full_name` was `repository_a`'s — proving `Commit#status` for `stack_b` was set by a payload never associated with `repository_b`.
5. Call `stack_b.send(:should_resume_continuous_delivery?, commit_b)` and `stack_b.send(:should_delay_continuous_delivery?, commit_b)` and assert both return `false`.
6. Stub/mock `stack_b.trigger_deploy` and call `stack_b.trigger_continuous_delivery`, asserting `trigger_deploy` is invoked with `commit_b` — demonstrating the forged cross-repository status reaches `trigger_deploy` unblocked.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/stack.rb (L701-713)
```ruby
    def should_resume_continuous_delivery?(commit)
      (deployment_checks_passed? && !deployable?) ||
        deployed_too_recently? ||
        commit.nil? ||
        commit.deployed?
    end

    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
    end
```
