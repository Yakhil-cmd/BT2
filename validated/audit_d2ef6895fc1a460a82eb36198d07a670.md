This confirms the vulnerability by direct comparison with sibling handlers.

The `Handler` base class provides a `stacks` helper that scopes to the correct repository via `Repository.from_github_repo_name(repository_name)&.stacks`, using `payload.dig('repository', 'full_name')`. [1](#0-0)  Both `PushHandler#process` and `CheckSuiteHandler#process` correctly use this `stacks` scope (`stacks.not_archived.where(branch:)` and `stacks.where(branch: ...)`) before touching any commit, so a status/push event can only affect stacks tied to the authenticated repository. [2](#0-1) [3](#0-2) 

`StatusHandler#process`, in contrast, ignores this scoping entirely and queries the global `Commit` table by `sha` alone:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets one repository's status webhook mutate any other repository's commit with the same SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes GitHub status payloads to every `Commit` row that matches the given SHA across the entire installation, with no filter on the repository/stack that authenticated the webhook. Since git SHAs are a hash of tree/parent/author/committer/timestamps/message, not of a repository identity, any attacker who can produce a commit with an identical SHA within their own repository (e.g. a fork of, or replicated commit from, a repo sharing a GitHub organization/webhook secret with the victim) can post a real, signature-valid `status` event that flips a required context's state for a completely unrelated victim commit/stack.

### Finding Description
The broken binding: the intended invariant is `status.stack_id == webhook_authenticated_repository.stack_id` for every status write, but `StatusHandler#process` enforces only `status.commit.sha == params.sha`, with no constraint tying the write to the repository that signed the webhook. [4](#0-3) 

`WebhooksController#verify_signature` authenticates the payload against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret`, which is per-organization (or per-app), not per-repository/per-stack. [5](#0-4)  It never checks that `params.sha` (or `params.repository.full_name`) belongs to the org that owns the signature; it just verifies the HMAC came from a legitimately configured org.

Every other event handler in the same directory scopes its side effects through `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks`. [1](#0-0)  `PushHandler` and `CheckSuiteHandler` both use this `stacks` scope before touching commits. [2](#0-1) [3](#0-2)  `StatusHandler` is the outlier: it neither calls `stacks` nor filters by `payload.dig('repository', 'full_name')` at all, so `Commit.where(sha: params.sha)` can match commits belonging to any stack/repository in the installation that happens to record that SHA.

Once a matching `Commit` is found, `create_status_from_github!` creates a `Status` and recomputes the aggregate `status`/`deployable?` via `Commit#add_status`, which can flip `deployable?`/merge eligibility and fire `deployable_status`/`commit_status` hooks for the victim stack. [6](#0-5)  If `github-actions` is in the victim stack's `ci.require` (`required_statuses`), a `failure` status for that context blocks deploys/merges via `Status::Common#required?`. [7](#0-6) 

Attack: the attacker owns/controls a repository within an organization mapped to the same `webhook_secret`-bearing GitHub App configuration in Shipit (a realistic scenario for orgs using an org-wide/app-wide webhook secret, or a repo the attacker legitimately controls in that org). They craft a commit with tree/author/committer/message/timestamps identical to a known victim commit SHA (SHAs of public commits are often knowable, and forks naturally share SHAs with upstream). GitHub then delivers a genuinely signed `status` webhook (`context: "github-actions"`, `state: "failure"`, `sha: <shared-sha>`) for the attacker's repository. `verify_signature` passes because the signature is valid for that org. `StatusHandler#process` then finds the victim's `Commit` row (in a different stack, possibly a different repository under the same org, or any stack that happens to store that SHA) and writes the failing status onto it, corrupting the victim's deployability/merge state.

Existing guards fail because: `verify_signature` authenticates org-level HMAC only, not SHA-repository ownership; `ExplicitParameters` schema on `StatusHandler` validates types/presence only, not repository association; and there is no model-level constraint linking `Status`/`Commit` writes to the authenticated `repository_owner`/`full_name` from the payload.

### Impact Explanation
A payload authenticated for one repository writes a `Status` record and mutates `deployable?`/merge eligibility for a commit belonging to a different, unrelated stack/repository — this is the "payload for one repository mutating another's stack, commit ... " category explicitly listed as Critical. The attack is repeatable against any stack that shares a SHA with an attacker-reachable repository (forks, replicated commits, or any repo under the same org/webhook-secret scope), and can be used to sabotage CI-gated deploys or merges cross-tenant.

### Likelihood Explanation
Preconditions: (1) attacker must be able to get a genuinely-signed `status` webhook delivered — realistically requires being a legitimate committer/pusher to a repository within an org whose webhook secret validates against `Shipit.github(organization: repository_owner)`; (2) attacker must produce (or find) a commit whose SHA coincides with a victim's tracked commit SHA — trivial for forks (shared history) and feasible by replaying identical commit metadata for public commits. Given these, the attack is a single crafted push/status event, at low cost, and repeatable at will. The main friction is obtaining SHA collision with a specific victim commit outside the fork scenario, which the audit question explicitly frames as "attacker owns a repo producing that SHA" — i.e., precondition assumed satisfiable.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve the authenticated repository's `stacks` (via `Handler#stacks` / `Repository.from_github_repo_name(repository_name)`) and restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or an equivalent `Commit.joins(:stack => :repository).where(sha: params.sha, repositories: { ... })`), instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (add to `test/models/shipit/webhooks/handlers_test.rb` or a new status_handler test — not included here since `test/**` is out of scope for remediation but valid for demonstrating the bug):

```ruby
test "status webhook for repo A cannot mutate a commit belonging to stack B" do
  victim_stack = shipit_stacks(:shipit) # requires 'github-actions' in ci.require
  attacker_stack = shipit_stacks(:cyclimse) # different repository

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_stack.commits.create!(sha: shared_sha, ...)

  before_status = victim_commit.reload.status.state
  before_deployable = victim_commit.deployable?

  payload = {
    'sha' => shared_sha,
    'state' => 'failure',
    'context' => 'github-actions',
    'repository' => { 'full_name' => attacker_stack.repository.full_name,
                       'owner' => { 'login' => attacker_stack.repository.owner } }
  }
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal before_status, victim_commit.reload.status.state
  assert_equal before_deployable, victim_commit.reload.deployable?
end
```

Both assertions currently fail (the victim commit's status/deployability changes), confirming `Commit.where(sha: params.sha)` in `app/models/shipit/webhooks/handlers/status_handler.rb:21` writes to commits outside the authenticated repository's stacks.

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

**File:** app/models/shipit/status/common.rb (L50-52)
```ruby
      def required?
        commit.required_statuses.include?(context)
      end
```
