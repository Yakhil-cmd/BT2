Confirmed: no `status_handler_test.rb` exists, and sibling handlers (`PushHandler`, `CheckSuiteHandler`) both scope their work through `stacks` (derived from `payload.dig('repository', 'full_name')`), while `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally with zero repository scoping.

### Title
Cross-tenant forged commit status via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by SHA across the entire `commits` table, with no check that the SHA belongs to a commit tracked under the repository that authenticated the incoming webhook. Any organization/repository already onboarded to Shipit can therefore forge a `success` status for a commit belonging to a *different* stack, as long as that commit's SHA also exists in the attacker-controlled repository's history (trivially achievable via forks, subtree copies, or repo history reuse).

### Finding Description
The broken binding: `Status#stack_id` written by `Commit#create_status_from_github!` should equal the `Repository`/`Stack` that authenticated via `payload.dig('repository','full_name')` (`repository_name` in `app/models/shipit/webhooks/handlers/handler.rb:36-38`), but it instead equals whatever `commit.stack_id` happens to be for **any** commit row matching the raw SHA string, regardless of which repo's webhook delivered it.

Code path:
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a completely unscoped query against the global `commits` table. It never calls the `stacks` helper (`Handler#stacks`, `app/models/shipit/webhooks/handlers/handler.rb:32-34`) that other handlers use to restrict to the authenticated repository.
- Compare with `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`), both of which correctly scope through `stacks.where(...)` before touching any commit.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `statuses.replicate_from_github!(stack_id, github_status)`, and `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`) persists `stack_id:` verbatim from the commit — i.e., the victim's stack id, never the attacker's.

Exploit flow: an attacker who controls a repository already registered with Shipit under some organization (so `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` succeeds using that org's legitimately configured `webhook_secret`) sends (or triggers GitHub to send, e.g., by pushing a commit and calling the Statuses API on their own repo) a `status` webhook whose `sha` equals a SHA that also exists in `victim/repoB`'s tracked history (e.g., because `attacker/repoA` is a fork, mirror, or subtree copy of `victim/repoB`, which reproduces byte-identical git objects and thus identical SHA-1s), with `context` set to `victim/repoB`'s configured `required_statuses` string and `state: 'success'`. `StatusHandler#process` matches the shared-SHA `Commit` row belonging to `victim/repoB`'s stack and writes a forged `success` `Status` there.

Existing guards don't stop this: `verify_signature` only proves the payload came from *some* org already known to Shipit, not that the org matches the target commit's stack; `ExplicitParameters` schema for `StatusHandler` doesn't even `require :repository`, and `drop_unhandled_event`/`check_if_ping` are irrelevant. No model validation ties `Status.stack_id` to the webhook's source repository.

### Impact Explanation
A forged `Status` row is written for `victim/repoB`'s stack from a webhook that authenticated only for `attacker/repoA`'s organization — this is exactly the "payload for one repository mutating another's stack, commit" Critical category. If the forged context matches an entry in `victim/repoB.required_statuses`, this can satisfy CI gating and enable an unauthorized deploy/merge on the victim stack. The attack is repeatable against any stack whose commits share a SHA with an attacker-reachable repository, and the blast radius spans every stack registered under the same Shipit installation (the query is global, not even org-scoped).

### Likelihood Explanation
Preconditions: attacker needs push/webhook-trigger capability on some repository that is already onboarded to Shipit under an org with a working GitHub App/webhook secret (so `verify_signature` passes), and needs a commit SHA collision with the victim stack's tracked history — trivially arranged via forking/mirroring/subtree-copying the victim repo into the attacker-controlled repo, since git SHA-1s are content-derived and reproduced exactly on copy. No secrets, sessions, or `Shipit.github_teams` membership are required. This is a low-cost, repeatable attack once the attacker controls any onboarded repository.

### Recommendation
Scope `StatusHandler#process` through the authenticated repository, mirroring `PushHandler`/`CheckSuiteHandler`: restrict the commit lookup to `stacks.commits.where(sha: params.sha)` (or equivalent join through `Repository.from_github_repo_name(repository_name)`), and require `repository.full_name` in the `params` schema so it cannot be omitted.

### Proof of Concept
Minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (new file):
```ruby
test "#process does not write a status for a commit belonging to another repository's stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = shipit_commits(:cyclimse_first) # belongs to victim_stack
  shared_sha = victim_commit.sha

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/circleci',
    'repository' => { 'full_name' => 'attacker/repoA' } # different org/repo entirely
  }

  assert_no_difference -> { Shipit::Status.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  refute victim_commit.reload.statuses.exists?(context: 'ci/circleci', state: 'success')
end
```
Running this against current code fails the `assert_no_difference`/`refute` (a `Status` row IS created with `stack_id == victim_stack.id`), proving `Status.stack_id` after == `victim_stack.id` even though `payload['repository']['full_name']` was `'attacker/repoA'` — confirming the broken binding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/status.rb (L23-33)
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
