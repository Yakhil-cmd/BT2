### Title
`StatusHandler#process` updates commits by bare SHA with no repository scoping, allowing a status forged from one repository to flip CI state on another repository's (production) stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` across the entire database and writes the incoming GitHub status to every matching `Commit`, ignoring which repository the webhook actually came from. All other handlers use the base `Handler#stacks` helper, which scopes lookups to `Repository.from_github_repo_name(repository_name)`, but `StatusHandler` bypasses this scoping entirely.

### Finding Description
The broken binding is: a `status` webhook authenticated for repository `R` (`payload.dig('repository','full_name') == R`) should only be allowed to write `Status` records onto `Commit` rows belonging to stacks of `R` — i.e. `commit.stack.repository == R`. The code does not enforce this.

`Handler` defines a repo-scoping helper that other handlers use: [1](#0-0) 

But `StatusHandler#process` never calls `stacks` or filters by repository; it queries every commit with the matching SHA, unscoped: [2](#0-1) 

`Commit#create_status_from_github!` then writes the status and immediately re-evaluates deployability/merge scheduling on whatever stack owns that commit row: [3](#0-2) [4](#0-3) 

`verify_signature` in the controller only proves the webhook was really sent by GitHub for the *organization* named in the payload (`repository_owner`), using that org's registered GitHub App/secret — it says nothing about which specific repository within that org the status belongs to, and it never cross-checks that the `sha` in the payload actually belongs to the repository that authenticated the request: [5](#0-4) 

Exploit flow:
1. Attacker controls (or has push access to) a GitHub repository `A` that is a fork of, or shares commit history with, the victim's tracked repository `B` — both under the same GitHub organization/App installation trusted by Shipit (so `verify_signature` succeeds against the shared org secret). Because Git SHAs are content-addressed, any commit shared between `A` and `B` (common ancestor, cherry-pick, mirrored history) has an identical SHA in both.
2. Attacker sets a commit status (`context: ci/integration`, `state: success` or `failure`) on repository `A` for that shared SHA via the normal GitHub Status API — an action fully within their own repo's permissions.
3. GitHub sends a correctly signed webhook to Shipit's `POST /webhooks` for repository `A`. `check_if_ping`, `drop_unhandled_event`, and `verify_signature` all pass, since the request is a genuine GitHub webhook for a trusted org.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which returns the matching `Commit` row belonging to the victim's stack for repository `B` as well (since the query has no `stack_id`/repository filter), and writes the forged status onto it.
5. If `B`'s production stack requires `ci/integration`, the forged `success` status can make a pending/blocked commit `deployable?` and trigger `schedule_continuous_delivery` → `ContinuousDeliveryJob`, or a forged `failure` can `block?` an otherwise good commit.

No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) checks that the SHA belongs to the authenticated repository — the schema only validates parameter types/shape, not cross-record scoping.

### Impact Explanation
A webhook correctly authenticated for repository `A` can write a `Status` record onto a `Commit` belonging to a different repository/stack `B`'s stack, satisfying the "payload for one repository mutating another's stack/commit" criterion. If `B` is a production environment stack gated on `ci/integration`, this can force an unauthorized deploy (forged success unblocking `deployable?`/continuous delivery) or an unauthorized block/rollback prevention (forged failure). This is repeatable for any SHA shared between an attacker-reachable repository and a victim stack's commit history, and generalizes to any repository under the same trusted GitHub App/org whose history overlaps with a target.

### Likelihood Explanation
Preconditions: attacker needs push/status-setting rights on some repository whose GitHub organization is already trusted by Shipit's `verify_signature` (i.e., a Shipit-configured GitHub App installation), and a SHA that is shared with the victim's tracked commit history (trivially achieved via forks, shared history, or reused template/initial commits). No Shipit credentials, sessions, or GitHub secrets are required — only ordinary repository status-setting permission on a repo the attacker already controls. This is low-cost and repeatable per shared SHA.

### Recommendation
Scope `StatusHandler#process` the same way other handlers are scoped: resolve the authenticating repository via `stacks`/`Repository.from_github_repo_name(payload.dig('repository','full_name'))` and restrict the `Commit` lookup to `commit.stack_id` values belonging to that repository (e.g., `Repository.from_github_repo_name(repository_name)&.stacks&.flat_map(&:commits)&.where(sha: params.sha)` or equivalent `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), rather than an unscoped `Commit.where(sha:)`.

### Proof of Concept
minitest sketch:
```ruby
test "status webhook does not update commits belonging to a different repository" do
  repo_a = shipit_repositories(:repo_a) # attacker's authenticated repo
  repo_b = shipit_repositories(:repo_b) # victim's production repo
  stack_b = shipit_stacks(:production_stack, repository: repo_b, environment: 'production')
  shared_sha = 'a' * 40
  commit_b = stack_b.commits.create!(sha: shared_sha, message: 'shared commit')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/integration',
    'repository' => { 'full_name' => repo_a.full_name, 'owner' => { 'login' => repo_a.owner } },
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  commit_b.reload
  # Binding under test: commit_b.statuses should remain empty because the webhook
  # authenticated repo_a, not repo_b.
  assert_empty commit_b.statuses, "status for repo_a leaked into repo_b's commit"
end
```
This fails on current code because `StatusHandler#process` writes the status to `commit_b` regardless of `payload['repository']`.

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
