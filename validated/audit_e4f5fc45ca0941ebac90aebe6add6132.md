### Title
Cross-tenant Commit mutation via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` with no repository scoping, unlike `PushHandler` and `CheckSuiteHandler`, which filter through `Handler#stacks` (`Repository.from_github_repo_name(repository_name)&.stacks`). Any webhook signed for an attacker-owned repository whose payload names a `sha` that also exists on a victim's `Commit` row will write a `Status` onto that victim commit, regardless of which repository actually owns it.

### Finding Description
The intended binding across all webhook handlers should be: `payload['repository']['full_name'] == repository owning the mutated Stack/Commit row`. `Handler#stacks` enforces exactly this: [1](#0-0) 
`PushHandler#process` and `CheckSuiteHandler#process` both mutate only through `stacks`, so a payload naming the attacker's own repository can only reach stacks tied to that repository: [2](#0-1) [3](#0-2) 

`StatusHandler#process`, by contrast, queries `Commit` directly by `sha` with no repository/stack scoping at all: [4](#0-3) 

`repository_name`/`repository_owner` from the payload is used only for signature verification (choosing which GitHub App/org secret to check), not for authorizing *which row* gets mutated: [5](#0-4) 

Because `sha` is a git content hash, it is not repository-scoped in git itself: a forked repository shares commit objects (and thus identical SHAs) with its upstream, and independent repositories can coincidentally or deliberately contain identical commit content (e.g., cherry-picks, mirrors, subtree/vendor copies). The `commits` table itself is only unique on `(sha, stack_id)`, confirming the same `sha` is expected to legitimately exist under multiple stacks simultaneously: [6](#0-5) 

Exploit flow: attacker owns/controls a repository registered in Shipit (e.g., a public fork of the victim's repository, or a repo containing a duplicate/cherry-picked commit). Attacker sends a valid, signature-verified `status` webhook whose `repository.full_name` is the attacker's own repo, but whose top-level `sha` field matches a commit SHA that also exists in a victim stack's `Commit` table. `StatusHandler` finds `Commit.where(sha: params.sha)` across the entire database - including the victim's row - and calls `commit.create_status_from_github!(params)` on it, writing a `Status` (state/description/target_url/context, all attacker-controlled) onto the victim's commit. The same attack via `push` or `check_suite` events has no effect on the victim because both are filtered through `Repository.from_github_repo_name(attacker_repo).stacks`, which never resolves to the victim's stack.

### Impact Explanation
The attacker can inject arbitrary CI/status data (`state`, `description`, `target_url`, `context`) onto a commit belonging to a stack/repository they do not own or control, without ever authenticating against that repository. Since `Commit#state`/`#deployable?` derive from `statuses`, and status changes trigger `deployable_status` hooks and `ProcessMergeRequestsJob` (continuous-delivery/merge-request flows), an attacker can flip a victim commit's CI state (e.g., force a `success` status), potentially unblocking a deploy gate or merge-request auto-merge condition that depends on required status checks. This is a payload for one repository mutating another repository's `Commit` state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions are modest and match the stated attacker capability set: the attacker only needs a repository of their own registered in Shipit with a working webhook (a normal, unprivileged onboarding action), and a `sha` value that collides with a victim's commit. This is realistic for forks of public victim repositories (SHAs are identical across fork and upstream by git's content-addressing) or for any commit content duplicated across repos. No Shipit secrets, sessions, or elevated GitHub permissions are required - only the ability to fire a `status` event referencing the target SHA (e.g., via a CI integration or a raw signed webhook from the attacker's own repo). The attack is repeatable against any victim commit whose SHA the attacker can produce or already knows.

### Recommendation
Scope `StatusHandler#process` through `stacks` the same way `PushHandler`/`CheckSuiteHandler` do, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status webhook can only mutate commits belonging to stacks backed by the repository named in its own payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_scoping_test.rb (conceptual)
test "status webhook mutates a commit belonging to a different repository (cross-tenant write)" do
  attacker_repo = shipit_repositories(:attacker_repo) # full_name: "attacker/evil-repo"
  victim_stack  = shipit_stacks(:victim_stack)         # repository full_name: "victim/secure-repo"
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, author: shipit_users(:walrus),
                                                committer: shipit_users(:walrus),
                                                authored_at: Time.now, committed_at: Time.now)

  payload = {
    'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => 'attacker' } },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/fake',
  }

  assert_difference -> { victim_commit.reload.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  assert_equal 'success', victim_commit.reload.state # attacker-controlled state now on victim commit
end

test "push webhook naming attacker repo has no effect on victim stack with matching sha" do
  attacker_repo = shipit_repositories(:attacker_repo)
  victim_stack  = shipit_stacks(:victim_stack)
  victim_commit = victim_stack.commits.create!(sha: "b" * 40, author: shipit_users(:walrus),
                                                committer: shipit_users(:walrus),
                                                authored_at: Time.now, committed_at: Time.now)

  payload = {
    'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => 'attacker' } },
    'ref' => 'refs/heads/main',
    'after' => victim_commit.sha,
  }

  Shipit::Stack.any_instance.expects(:sync_github).never # victim_stack must never be touched
  Shipit::Webhooks::Handlers::PushHandler.call(payload)
  assert_equal 0, victim_stack.reload.commits.where(sha: victim_commit.sha).first.statuses.count
end
```
This pair demonstrates the exact asymmetry: `PushHandler` (via `Handler#stacks`) is correctly scoped to the attacker's own repository and cannot affect `victim_stack`, while `StatusHandler`'s unscoped `Commit.where(sha:)` lookup mutates the victim's `Commit#statuses` using an attacker-signed, attacker-named-repository webhook.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
