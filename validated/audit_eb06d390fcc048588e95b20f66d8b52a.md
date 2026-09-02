### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` allows an attacker to write a `failure`/`error` status onto a victim's commit and block deploys/merges - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no join or filter on the repository that authenticated the webhook, so a validly-signed `status` webhook from an attacker's own repository can write a `Status` row against any `Commit` in the database that happens to share that SHA, including one belonging to a victim's stack. This lets an attacker record a `failure`/`error` state for a victim's commit, flipping `Commit#deployable?` to false and blocking `Stack` continuous delivery/merge for that commit - the same missing-scoping bug previously identified for the "success" escalation case, but used here for denial (sabotage) instead of privilege escalation.

### Finding Description
Binding that should hold: `repository authorizing the status write == repository owning the Commit row being mutated`, i.e. `payload.repository.full_name == commit.stack.repository.full_name`. The code never checks this.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`params` only requires `:sha` and `:state` (plus optional description/target_url/context/created_at/branches) — there is no `repository`/`stack_id` field constraining the query: [2](#0-1) 

`WebhooksController#verify_signature` only proves that the payload's `repository_owner` field matches a GitHub App/organization known to Shipit and that the signature was produced with that organization's webhook secret — it says nothing about which specific `Commit`/`Stack` rows the `sha` in the body is allowed to touch: [3](#0-2) 

Exploit flow: the attacker owns (or controls) a repository/organization that is legitimately connected to Shipit (so they can produce a validly-signed webhook using their own installation's secret). They send `POST /webhooks` with `X-Github-Event: status`, a body whose `repository` field points at their own repo (so signature verification passes) but whose `sha` field is set to a SHA that also exists as a `Commit` row in the victim's stack (e.g., a shared upstream/base commit, a cherry-picked commit, or a commit intentionally crafted/found to collide across the two repos' Shipit-tracked history) and `state: "failure"`. `StatusHandler#process` finds and mutates every `Commit` with that SHA regardless of which stack/repository it belongs to, calling `commit.create_status_from_github!(params)` on the victim's `Commit` too: [4](#0-3) 
This creates a `Status` row (`state: failure`/`error`) on the victim's commit, which recomputes `commit.state`/`deployable?` and fires `deployable_status`, blocking merge/deploy logic gated on commit deployability (`ProcessMergeRequestsJob`/continuous delivery triggers), as shown by the existing test suite's transition/webhook-firing behavior around `add_status`/`create_status_from_github!`: [5](#0-4) [6](#0-5) 

None of the existing guards close this gap: `verify_signature` authenticates the organization of the sender, not the target repository of the SHA being mutated; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema for `StatusHandler` validates types, not repository scope; and `Commit.where(sha:)` has no `stack_id`/`repository` predicate anywhere in the query.

### Impact Explanation
Any commit SHA reachable to a victim stack (via shared history, forks, cherry-picks, or coincidental cross-repo SHA collisions in the Shipit instance) can have an attacker-controlled `Status` row (state `failure`/`error`) written against it from a webhook the attacker legitimately signs for their own, unrelated repository. This is a cross-repository write of another repository's `Commit`/`Status` data (matching the listed Critical impact "a payload for one repository mutating another repository's stack, commit") and results in an unauthorized denial: the victim's commit is falsely marked undeployable, blocking deploys and any merge-request automation gated on CI success, across any tenant sharing the Shipit installation. Repeatable per SHA/commit and requires no privileged role, session, or secret beyond the attacker's own legitimate webhook signing key for their own repo.

### Likelihood Explanation
Preconditions: the attacker needs a repository/organization already connected to Shipit (satisfiable by any org owner integrating their own repo with the Shipit instance, which is an unprivileged self-service action in many deployments) and a SHA that also appears as a tracked `Commit` in the victim's stack. Attacker cost is a single crafted, validly-signed `POST /webhooks` request; the attack is trivially repeatable against any known/discoverable overlapping SHA. The main constraint is finding/engineering a SHA collision across repositories, which is realistic for forked/shared-history repositories tracked as separate Shipit stacks.

### Recommendation
Scope the lookup in `StatusHandler#process` (and analogous handlers) to commits belonging to the stack(s) whose repository matches the authenticated webhook's `repository.full_name`/`repository_owner`, e.g. join through `Stack` on `github_repo_name` before selecting `Commit`s to update, instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status webhook from attacker's repo must not mutate a commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit) # e.g. repository "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)
  victim_commit.update!(sha: "deadbeefcafefeed00000000000000000000001")
  assert victim_commit.deployable?

  # Attacker owns "attacker/other-repo", which is also validly registered with Shipit,
  # so their webhook signature verifies successfully for their own org.
  attacker_payload = {
    'sha' => victim_commit.sha, # collides with victim's tracked commit sha
    'state' => 'failure',
    'context' => 'ci/attacker',
    'branches' => [{ 'name' => 'master' }]
  }.merge(
    'repository' => { 'full_name' => 'attacker/other-repo', 'owner' => { 'login' => 'attacker' } }
  ).to_json

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # attacker's own valid signature for their repo

  assert_no_difference -> { victim_commit.reload.statuses.count }, "attacker-signed webhook for a different repo must not write a Status on victim's commit" do
    post :create, body: attacker_payload, as: :json
  end

  assert victim_commit.reload.deployable?, "victim commit must remain deployable; it was not authorized by attacker's webhook"
end
```
Before the fix, this test fails: the attacker's cross-repo `state: failure` webhook creates a `Status` on `victim_commit`, flips `deployable?` to `false`, and would prevent `ProcessMergeRequestsJob`/continuous-delivery triggers from proceeding for the victim's stack — demonstrating the same unscoped `Commit.where(sha:)` binding violation as the success-case escalation, applied here as a denial/sabotage primitive.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** test/models/commits_test.rb (L671-712)
```ruby
    expected_webhook_transitions = { # we expect deployable_status to fire on these transitions, and not on any others
      'unknown' => %w[pending success failure error],
      'pending' => %w[success failure error],
      'success' => %w[failure error],
      'failure' => %w[success],
      'error' => %w[success]
    }
    expected_webhook_transitions.each do |initial_state, firing_states|
      initial_status_attributes = { state: initial_state, description: 'abc', context: 'ci/travis' }
      (expected_webhook_transitions.keys - %w[unknown]).each do |new_state|
        should_fire = firing_states.include?(new_state)
        action = should_fire ? 'fires' : 'does not fire'
        test "#add_status #{action} for status from #{initial_state} to #{new_state}" do
          commit = shipit_commits(:cyclimse_first)
          assert commit.stack.hooks.where(events: ['deploy_status']).size >= 1
          refute commit.stack.ignore_ci
          commit.statuses.destroy_all
          commit.reload
          unless initial_state == 'unknown'
            attrs = initial_status_attributes.merge(
              stack_id: commit.stack_id,
              created_at: 10.days.ago.to_formatted_s(:db)
            )
            commit.statuses.create!(attrs)
          end
          assert_equal initial_state, commit.state

          expected_status_attributes = { state: new_state, description: initial_state, context: 'ci/travis' }
          add_status = lambda do
            attrs = expected_status_attributes.merge(created_at: 1.day.ago.to_formatted_s(:db))
            commit.create_status_from_github!(OpenStruct.new(attrs))
          end
          expect_hook_emit(commit, :commit_status, expected_status_attributes) do
            if should_fire
              expect_hook_emit(commit, :deployable_status, expected_status_attributes, &add_status)
            else
              expect_no_hook(:deployable_status, &add_status)
            end
          end
        end
      end
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
