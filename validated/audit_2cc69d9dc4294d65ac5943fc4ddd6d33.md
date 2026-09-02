### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` amplified by `bot_login` auto-deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` writes a GitHub `status` webhook to every `Commit` row that matches the bare SHA string, with no constraint tying the write to the repository that actually authenticated the webhook. Every other webhook handler in the codebase (`CheckSuiteHandler`, `PullRequest::*Handler`) explicitly scopes to `Repository.from_github_repo_name(payload.repository.full_name)` / `Handler#stacks` before touching any record, but `StatusHandler` does not, so a status event signed for one repository can flip CI state on a `Commit` belonging to a completely different stack whenever the two share a literal SHA string.

### Finding Description
The broken invariant, stated as an equality that should hold but doesn't:

`StatusHandler#process` should satisfy: `written_commits == stacks.commits.where(sha: params.sha)` (i.e. only commits belonging to stacks of the repository that authenticated this webhook). Instead it performs: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }` — a global, unscoped lookup across the entire `commits` table, i.e. `written_commits == Commit.where(sha: params.sha)` for the whole database, with no reference to `payload['repository']` at all.

Contrast this with the base `Handler` class, which defines a properly scoped helper that other handlers use: [2](#0-1) 

and `CheckSuiteHandler`, which uses it correctly: [3](#0-2) 

`StatusHandler` never calls `stacks` or `Repository.from_github_repo_name`, even though its `params` schema doesn't even require a `repository` block: [4](#0-3) 

The signature verification (`WebhooksController#verify_signature`) only proves that the request was signed for *some* `repository_owner`'s GitHub App installation; it does not prove that the `sha`/`context`/`state` inside the payload actually belongs to a commit in that same repository's stacks: [5](#0-4) 

Since `Commit` rows are only uniquely indexed per `(stack_id, sha)` — not globally unique on `sha` — the same literal SHA string can legitimately exist in multiple stacks belonging to different repositories (e.g. a commit cherry-picked/rebased identically into a fork and its upstream, or the same repository backing two stacks/environments). An attacker who owns a repository that is itself onboarded to the same Shipit instance (any unprivileged GitHub user with push/fork access, per the threat model) can:
1. Get a real, correctly-signed `status` webhook emitted by GitHub for their own repo/SHA (by pushing a commit and setting a commit status via the GitHub API on a repo they control, or by any repo onboarded under an org with the same webhook_secret/installation).
2. Choose `context: "ci/jenkins"`, `state: "success"` (or `"failure"`) and a `sha` that is shared with a victim stack's commit.
3. `StatusHandler#process` matches the victim's `Commit` row purely on SHA text and calls `commit.create_status_from_github!`, which invokes `add_status`, which — on a state transition — calls `stack.schedule_merges` (via `Commit#add_status`): [6](#0-5) 

4. If the victim stack has `continuous_deployment` enabled or merge queue processing enabled, this newly-forged `ci/jenkins` success unblocks a deploy/merge that runs under the automated identity — which, when `bot_login` is configured, is `Shipit.user` (`User.find_or_create_by_login!(github.bot_login)`): [7](#0-6) 

None of the existing guards (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema on `StatusHandler`) prevent this, because they validate only the *sender's* org signature and payload shape — not that the target `Commit` belongs to a stack of the repository that sent the webhook.

### Impact Explanation
An attacker who controls (or can trigger webhooks from) any repository onboarded to a shared Shipit instance can force a status write onto a `Commit` belonging to a different repository's stack, as long as the SHA text matches. This can unblock required-status gating and trigger `stack.schedule_merges`, leading to an unauthorized merge/deploy executed under the bot identity (`Shipit.user`) on the victim stack — matching the Critical category "a payload for one repository mutating another's stack, commit... or an unauthorized deploy, rollback or merge." The blast radius is bounded by SHA-collision opportunity across stacks (most realistic when the same GitHub repository or its forks back multiple stacks/environments), which is a common real-world Shipit deployment pattern (staging/production stacks on the same repo, or PR-based review stacks).

### Likelihood Explanation
Preconditions: (1) attacker must be able to get a validly-signed `status` webhook accepted by `verify_signature` for some registered org/installation (feasible for any repo owner whose repo/org is onboarded, e.g. their own fork under the same GitHub App installation); (2) the target SHA must exist as a `Commit` row in a victim stack sharing the literal SHA (realistic for shared/forked history or multi-stack-per-repo setups); (3) the victim stack must be configured to react to that status (required/blocking context, continuous deployment or active merge queue) — the question's premise of `bot_login` configured is exactly the common production configuration documented in `docs/setup.md`. Attacker cost is low: no Shipit session, API token, or secret is required — only the ability to emit a real webhook from a repo they already control. The attack is repeatable per webhook delivery.

### Recommendation
Scope `StatusHandler#process` the same way `CheckSuiteHandler` and the `PullRequest::*Handler`s do: require `repository.full_name` in the `params` schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the commit lookup to `stacks.commits.where(sha: params.sha)` (or equivalently `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { ... })`) instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (to be placed under `test/models/webhooks/handlers/status_handler_test.rb`):
```ruby
test "status webhook does not affect commits belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit) # repository A, bot_login configured (Shipit.user)
  attacker_repo_full_name = "attacker/other-repo" # repository B, distinct from victim_stack.repository

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
                                                committer: shipit_users(:walrus),
                                                authored_at: Time.now, committed_at: Time.now,
                                                message: "shared sha commit")

  # Binding under test:
  # expected: victim_commit.statuses.where(context: 'ci/jenkins').count == 0 (no repo B authorized this write)
  # actual:   StatusHandler#process writes it anyway because it queries Commit.where(sha:) with no repo scope
  assert_equal 0, victim_commit.statuses.where(context: 'ci/jenkins').count

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/jenkins",
    "repository" => { "full_name" => attacker_repo_full_name, "owner" => { "login" => "attacker" } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # Fails today: the forged status is written even though the payload's repository
  # (attacker/other-repo) never authenticated for victim_stack.repository.
  assert_equal 0, victim_commit.statuses.where(context: 'ci/jenkins').count,
    "status for ci/jenkins from an unrelated repository must not land on the victim stack's commit"
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** lib/shipit.rb (L208-214)
```ruby
  def user
    if github.bot_login
      User.find_or_create_by_login!(github.bot_login)
    else
      AnonymousUser.new
    end
  end
```
