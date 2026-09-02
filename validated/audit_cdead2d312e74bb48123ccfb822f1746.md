### Title
Cross-tenant `Status` write via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone, across the entire `Commits` table, and calls `create_status_from_github!` on every match, without ever consulting `Handler#stacks` (which scopes by `payload.dig('repository', 'full_name')`). By contrast, `PushHandler` and `CheckSuiteHandler` both scope their work through `stacks` before touching any `Commit`. This lets a webhook that is validly signed for one repository/org write a `Shipit::Status` onto a `Commit` belonging to a completely different `Stack`/`Repository`, as long as the two share a `sha` value (e.g., the well-known empty-tree sha `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any other coincidentally shared commit).

### Finding Description
The claimed binding is: `repository verified by webhook_secret` == `repository whose Commit#stack receives the write`. Tracing the code shows this does not hold for the `status` event.

- `Shipit::WebhooksController#verify_signature` only checks that the HMAC signature matches the `webhook_secret` configured for `repository_owner` (`payload.dig('repository', 'owner', 'login')` or `organization.login`) [1](#0-0) . It never checks or constrains which repository's data may subsequently be mutated — it authenticates the *sender org*, not the *target repository/commit*.
- `Shipit::Webhooks::Handlers::Handler#stacks` is the only mechanism designed to scope handler behavior to the repository named in the payload: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none`, where `repository_name = payload.dig('repository', 'full_name')` [2](#0-1) .
- `PushHandler#process` correctly uses `stacks.not_archived.where(branch:)` before acting [3](#0-2) , and `CheckSuiteHandler#process` uses `stacks.where(branch: ...)` then `stack.commits.where(sha: ...)`, scoping the sha lookup to commits belonging to stacks of the named repository [4](#0-3) .
- `StatusHandler#process`, however, does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped ActiveRecord query against the entire `commits` table, with no reference to `stacks`, `repository_name`, or any repository/stack filter at all [5](#0-4) . `Commit#create_status_from_github!` then unconditionally creates a `Status` row scoped to that commit's own `stack_id` [6](#0-5) .

Exploit flow: an attacker who legitimately controls (or can push to/trigger CI on) a repository tracked by Shipit under some org — with that org's `webhook_secret` correctly configured — can post a `status` event whose `sha` equals a commit sha that also exists as a `Commit` row under a different `Stack`/`Repository` (any repo sharing that org's Shipit instance, or, if the Shipit instance is multi-org, any org, since the `webhook_secret` check is per-org and has no bearing on which `Commit` rows get matched). Git commit shas can coincide across unrelated repositories in several realistic ways (e.g. the canonical empty-tree/empty-commit sha, cherry-picked or shared-history commits, or vendored subtree merges), and the attacker fully controls the commit history and CI status reporting for their own repo, so they can reliably choose or search for a colliding sha. The forged/legitimate webhook is delivered with `repository.full_name` set to the attacker's own repo (this is what makes it pass `verify_signature`), but `StatusHandler` never checks that field, so the write lands on the victim's `Commit`/`Stack` regardless.

None of the listed guards prevent this: `verify_signature` authenticates the org, not the target repo; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/type of `sha`/`state`/etc., not repository ownership; there is no model validation on `Status` or `Commit` that cross-checks the incoming payload's repository against the commit's stack.

### Impact Explanation
A `Shipit::Status` record (state, description, target_url, context) is written onto a `Commit` belonging to a `Stack`/`Repository` that never authenticated or authorized the write — this is a cross-repository/cross-tenant database mutation, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Since `Status` state feeds `Commit#deployable?`/`Commit#blocked?` and can influence CI-gating logic used before deploys [7](#0-6) , a forged `success` status can help clear CI gates for a victim commit it was never actually validated for, and `create_status_from_github!` also fires `deployable_status`/`commit_status` hooks and enqueues `ProcessMergeRequestsJob` (see `commits_test.rb` transition tests), amplifying the blast radius beyond just a DB row. The attack is repeatable at will against any sha the attacker can predict or discover overlaps with a victim's commit history, across all stacks in the Shipit instance, not just one target.

### Likelihood Explanation
Preconditions are modest: the attacker needs a repository tracked by a Shipit instance under some org with a working `webhook_secret` (i.e., they are a normal, unprivileged contributor/owner of one repo in a multi-tenant Shipit deployment) and the ability to get GitHub to emit a `status` event for a chosen sha (trivial — post a commit status via the GitHub API/CI for a commit they control). Finding a colliding sha with a specific victim commit requires either luck, insider knowledge of a shared history/artifact, or use of universally-shared shas (empty tree/empty commit) which are commonly present across many repositories' histories. This makes the attack conceptually easy for shared "boilerplate" shas but non-trivial for targeting an arbitrary, specific victim commit; it is fully repeatable via automated status-posting once a target sha is known.

### Recommendation
Scope `StatusHandler#process` through `stacks` (or repository) the same way `PushHandler` and `CheckSuiteHandler` do, e.g. iterate `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`, so a status webhook can only write onto commits belonging to the repository that was actually verified by `webhook_secret`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status from repository A must not create a Status on a commit belonging to repository B's stack" do
  request.headers['X-Github-Event'] = 'status'

  victim_commit = shipit_commits(:first) # belongs to @stack (e.g. "shopify/shipit-engine")
  shared_sha = victim_commit.sha

  attacker_repo_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'attacker-ci',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'shopify' } }
  }.to_json
  # verify_signature succeeds because GithubHook#verify_signature is stubbed true in setup,
  # simulating a genuinely signed webhook from the attacker's own (different) repository.

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body: attacker_repo_payload, as: :json
  end
  # Expected to FAIL against current code: StatusHandler#process ignores
  # payload['repository']['full_name'] and matches purely on `sha`, creating
  # a Status on victim_commit despite the payload naming "attacker-org/attacker-repo".
end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
