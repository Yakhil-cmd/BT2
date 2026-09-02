### Title
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits by SHA alone, without scoping to the webhook's authenticated repository/org, allowing cross-tenant status forgery - (`File: app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and applies the webhook's `state` to every match, with no check that the matched commit's `stack.repository` corresponds to the organization that authenticated the webhook. Every other handler (`PushHandler`, `CheckSuiteHandler`, `PullRequest::*`) scopes exclusively to `stacks` derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, but `StatusHandler` does not, breaking the org-to-stack binding the security model relies on.

### Finding Description
The binding that must hold: **org authorizing the Status webhook (`repository_owner` verified in `WebhooksController#verify_signature`) == org owning the `Stack` whose commit receives the Status**. This binding is enforced everywhere else via `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` from the payload's own `repository.full_name` [1](#0-0) , and is used by `PushHandler` [2](#0-1) 
and `CheckSuiteHandler` [3](#0-2) .

`StatusHandler` breaks this pattern entirely: [4](#0-3) 
It queries `Commit` globally by `sha`, with no join/filter on `repository_name`/`repository_owner` from the payload, and calls `commit.create_status_from_github!(params)` for every match regardless of which stack/org that commit belongs to.

`Commit` records are stored per-stack (index on `(stack_id, sha)`, per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), so the same commit SHA can legitimately exist in multiple independent stacks/orgs if a Shipit instance hosts multiple GitHub organizations (explicitly supported per `docs/setup.md`'s "Using Multiple Github Applications" section, which is config, not code, but establishes the multi-tenant threat model the engine must defend). An attacker who administers *any* org onboarded to the same Shipit instance can legitimately sign a "status" webhook using their own org's real `webhook_secret` (passing `WebhooksController#verify_signature`, which validates the signature against `Shipit.github(organization: repository_owner)` for the attacker's own, correctly-owned org) [5](#0-4) 
but set `sha` in the payload to the SHA of a commit belonging to a *victim* stack in a different org. Since GitHub SHAs are public (visible via the victim's own repository or public Shipit UI), no secret or preimage attack is needed — only knowledge of the string value.

`StatusHandler` will match the victim's `Commit` row purely by SHA and call `create_status_from_github!`, which calls `add_status` → `statuses.replicate_from_github!(stack_id, ...)` using the *victim commit's own* `stack_id` (from the `Commit` object, not the payload), creating a `Status` for the victim's stack [6](#0-5) .
`Status#after_commit` schedules continuous delivery immediately [7](#0-6) 
which is delegated to `commit.schedule_continuous_delivery`, ultimately reaching `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → `Stack#next_commit_to_deploy` [8](#0-7) .
Because `Commit#deployable?` only checks `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [9](#0-8) ,
the forged `success` state makes the victim's commit deployable, and `deployable_commits` [10](#0-9) 
selects it. This triggers `build_deploy`/`trigger_deploy` on the victim stack using CI evidence forged entirely by the unrelated attacker org.

None of the listed guards prevent this: `verify_signature` only validates that the payload's claimed org matches *some* configured org and its secret — it never re-validates that the `sha` inside the payload belongs to a commit owned by that same org's repository. `drop_unhandled_event`, `ExplicitParameters` schema, `force_github_authentication`, `User#authorized?`, model validations, and `EnvironmentVariables#permit` are irrelevant to this code path, since no user session or API client is involved at all — the entire chain runs off the raw webhook payload.

### Impact Explanation
An operator/attacker with legitimate, correctly-signed webhook access to Org B (an org with no relationship to the victim's Org A stack) can write a `Status` record for Org A's stack/commit and trigger an unauthorized deploy of Org A's pipeline using forged CI evidence — a payload for one repository mutating another's stack/commit and causing an unauthorized deploy, matching the **Critical** impact category explicitly listed in the rules. This is repeatable against any commit SHA the attacker can observe (which is public information) and against any org/stack sharing the Shipit instance, so the blast radius scales with the number of orgs configured on a single Shipit deployment (multi-tenant setups, as documented).

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (documented, supported feature) where the attacker legitimately administers at least one onboarded org with its own valid `webhook_secret`, and (2) knowledge of a target commit SHA in another org's stack (trivially public via GitHub or the victim's own Shipit UI). No Shipit session, API token, or victim-org secret is required. Attacker cost is a single signed HTTP POST to `/webhooks`; the attack is fully repeatable and scriptable against arbitrary SHAs/stacks on the same instance.

### Recommendation
In `StatusHandler#process`, scope commit lookup through `stacks` (as `PushHandler`/`CheckSuiteHandler` do), e.g. resolve commits only within `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`, ensuring the Status is only ever applied to a commit belonging to a stack whose `Repository` matches the payload's authenticated `repository.full_name`/owner.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
```ruby
test ":status from an unrelated organization forges CI state on a victim stack's commit" do
  victim_stack = shipit_stacks(:shipit)         # org "shopify"
  victim_commit = shipit_commits(:second)       # belongs to victim_stack, currently not success
  refute_predicate victim_commit, :deployable?

  before_next_commit = victim_stack.next_commit_to_deploy

  # Attacker legitimately owns/administers a *different* onboarded org ("attacker-org"),
  # with its own real webhook_secret, unrelated to victim_stack.repository.
  request.headers['X-Github-Event'] = 'status'
  forged_payload = {
    'sha' => victim_commit.sha,               # publicly known SHA of victim's commit
    'state' => 'success',
    'context' => 'ci/forged',
    'created_at' => Time.now.iso8601,
    'branches' => [{ 'name' => victim_stack.branch }],
    'repository' => { 'full_name' => 'attacker-org/unrelated-repo',
                       'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  assert_difference '@victim_commit.statuses.count', 1 do
    post :create, body: forged_payload, as: :json
  end

  assert_predicate victim_commit.reload, :deployable?
  assert_not_equal before_next_commit, victim_stack.reload.next_commit_to_deploy
  assert_equal victim_commit, victim_stack.next_commit_to_deploy

  deploy = victim_stack.trigger_continuous_delivery
  assert_equal victim_commit, deploy.until_commit
end
```
This asserts both sides of the binding explicitly: before the forged webhook `next_commit_to_deploy` does not select `victim_commit`; after it, `next_commit_to_deploy` changes identity to the forged-into-deployable commit, and the resulting `Deploy#until_commit` equals it — confirming the org-authorization binding is violated.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/stack.rb (L210-243)
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

    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end

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
