Confirmed. The critical finding is that `StatusHandler#process` bypasses the repository-scoping pattern used by every other handler.

## Finding [1](#0-0) 

Every other webhook handler (`CheckSuiteHandler`, all `PullRequest::*` handlers) scopes its lookups through `stacks` / `Repository.from_github_repo_name(repository_name)`, binding the mutation to the repository named in `payload['repository']['full_name']`: [2](#0-1) 

`StatusHandler`, by contrast, does a **global, unscoped** lookup by `sha` alone across the entire `commits` table, with no repository binding whatsoever: [3](#0-2) 

The broken binding, stated explicitly: it should be true that `commit.stack.repository.full_name == payload['repository']['full_name']` for any commit mutated by a status webhook — but `StatusHandler#process` never reads or checks `payload['repository']` at all, so this equality is never even evaluated.

Then, `Stack#next_commit_to_deploy` / `deployable_commits` walk undeployed commits in id order and pick the first one where `Commit#deployable?` is true: [4](#0-3) [5](#0-4) [6](#0-5) 

`deployable?` only checks `locked?`, `stack.ignore_ci?`, `success?`/`blocked?` — `success?` is delegated to `status`, which is built from whatever `Status` rows exist for that commit id, without checking which repository wrote them: [7](#0-6) [8](#0-7) 

**Exploit flow**: signature verification (`verify_signature`) only checks that the request is validly signed by *some* configured GitHub App/org — it uses `repository_owner` purely to pick which shared secret to check against, it does not verify that the resulting repository is the one the payload's commit actually belongs to: [9](#0-8) 

Given the audit's stated attacker capability ("emit webhooks from a repository they own"), an attacker who controls a repository/CI covered by the same GitHub App installation/webhook secret (this is explicitly granted in the rules as an attacker capability, and is a real-world consequence of GitHub App webhook secrets being shared across all installations of an app) can:
1. Obtain the victim's oldest-undeployed commit sha (commit shas are public, content-addressed, and typically visible via GitHub/Shipit UI).
2. Push an identical commit object (same content ⇒ same sha) into their own repository, or otherwise cause GitHub to emit a `status` event carrying that exact `sha`.
3. Set `state: success` and `context` matching the victim stack's `required_statuses` (from `cached_deploy_spec` — public/discoverable via the repo's `shipit.yml`).
4. GitHub signs this real event with the shared webhook secret; Shipit's `verify_signature` passes.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` **globally**, finds the victim's commit (regardless of which repository it actually belongs to), and calls `create_status_from_github!`, writing a `Status` row tied to `stack_id: commit.stack_id` — the victim's stack.
6. The victim commit now satisfies `Commit#deployable?`, and `Stack#next_commit_to_deploy`/`trigger_continuous_delivery` will select and deploy exactly that commit.

None of the guard rules cited in the prompt (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, model validations) block this, because they operate on signature/shape validity, not on repository-to-commit binding — and `StatusHandler` is the one handler that omits the `stacks`/`Repository.from_github_repo_name` scoping pattern used everywhere else in the same file/directory.

### Title
Global unscoped `Commit.where(sha:)` lookup in `StatusHandler` lets a status webhook from any repository write CI statuses onto another stack's commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire `commits` table, unlike every other webhook handler which scopes through `Repository.from_github_repo_name(payload['repository']['full_name'])`. A validly-signed `status` webhook naming a sha that happens to belong to a commit in a different stack/repository will apply a forged CI status to that unrelated commit.

### Finding Description
The broken binding: `commit.stack.repository.full_name` (the repo owning the targeted commit) must equal `payload['repository']['full_name']` (the repo the signed webhook claims to originate from) for the write to be authorized. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) never reads `payload['repository']` and performs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, so this equality is never checked. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) then persists a `Status` scoped to `commit.stack_id` regardless of which repository actually sent the webhook. Downstream, `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) and `Stack#next_commit_to_deploy`/`deployable_commits` (`app/models/shipit/stack.rb:235-243, 645-647`) consume this forged `success` status to select the targeted commit for deployment. `WebhooksController#verify_signature` only authenticates that the payload was signed by a GitHub App/org configured in Shipit's secrets — it does not verify that the signed repository matches the commit's owning repository, so a legitimately signed webhook from an attacker-controlled repository (sharing the same GitHub App webhook secret) is sufficient. Every sibling handler (`CheckSuiteHandler`, all `PullRequest::*Handler`) scopes through `Repository.from_github_repo_name`/`stacks`; `StatusHandler` is the outlier lacking this scoping.

### Impact Explanation
An attacker with a repository covered by the same shared GitHub App webhook secret can inject an arbitrary `Shipit::Status` row (state, context, description, target_url of their choosing) onto any commit sha in any stack hosted by the same Shipit instance, as long as they know or can produce that sha. This directly flips `Commit#deployable?` for a victim's commit, causing `Stack#trigger_continuous_delivery`/`next_commit_to_deploy` to select and deploy (or allow deployment of) a commit the victim's own CI never validated — an unauthorized deploy triggered by a payload for one repository mutating another repository's stack/commit state. This is repeatable against arbitrary shas/stacks and scales across all tenants (stacks) hosted by the same Shipit installation.

### Likelihood Explanation
Requires the attacker to control a repository whose `status` webhooks are signed with the same secret Shipit uses to validate signatures for the victim's organization (realistic under GitHub Apps, whose webhook secret is shared across all installations of the app, and under the audit's stated attacker capability of "emit webhooks from a repository they own"). Requires the attacker to know the target sha (public/content-addressed, generally discoverable) and the stack's `required_statuses` context (from the repo's own `shipit.yml`, typically public). No Shipit session, API token, or operator privilege needed. Cost is low: one crafted/replayed GitHub status event.

### Recommendation
Scope `StatusHandler#process` the same way as the other handlers: resolve the repository from `payload['repository']['full_name']` via `Repository.from_github_repo_name`, then restrict the `Commit.where(sha:)` lookup to `repository.stacks.commits` (or equivalently join through `stack.repository`) before applying `create_status_from_github!`, rejecting/ignoring shas that don't belong to that repository's stacks.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook from an unrelated repository can set a status on another stack's commit" do
  victim_commit = shipit_commits(:cyclimse_first) # belongs to some victim stack/repo
  victim_stack = victim_commit.stack
  required_context = victim_stack.required_statuses.first || 'ci/travis'

  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => required_context,
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }

  assert_difference -> { victim_commit.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)
  end

  victim_commit.reload
  assert_predicate victim_commit, :deployable?
  assert_equal victim_commit, victim_stack.next_commit_to_deploy
end
```

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

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```

**File:** app/models/shipit/stack.rb (L645-647)
```ruby
    def deployable_commits(commits)
      commits.to_a.reverse.find(&:deployable?)
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/status/common.rb (L50-52)
```ruby
      def required?
        commit.required_statuses.include?(context)
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
