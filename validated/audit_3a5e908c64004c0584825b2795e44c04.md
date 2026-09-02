### Title
Cross-tenant CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone, with no constraint tying the match to the organization/repository whose webhook secret actually verified the request. Since GitHub commit SHA1s are content-addressed and reproducible across independently owned repositories (e.g. an attacker forking or re-pushing a public upstream repo's history into their own org), a validly-signed `status` webhook from OrgA can create a `Status` on a `Commit` that belongs to OrgB's stack, and that status can trigger OrgB's `ProcessMergeRequestsJob`.

### Finding Description
The binding that should hold is: `repository_owner` (verified from the payload's `repository.owner.login` against `Shipit.github(organization: repository_owner)`'s `webhook_secret`) == `commit.stack.repository.owner` for every `Commit` mutated by the handler.

The verification step only checks the first half of this equality: [1](#0-0) [2](#0-1) 

It proves only that the raw bytes were signed with the secret registered for the organization named in `repository.owner.login` of the payload. It does not scope which `Commit` rows the payload is allowed to affect.

`StatusHandler#process` then performs an unscoped, cross-tenant lookup: [3](#0-2) 

`Commit.where(sha: params.sha)` matches every `Commit` row in the entire Shipit instance with that SHA, regardless of which stack/repository/organization it belongs to, and calls `commit.create_status_from_github!(params)` on each one. There is no filter such as `commit.stack.repository.owner == repository_owner` or `commit.stack.repository.full_name == params.dig(...)`.

Because git commit SHA1s are a hash of tree+parents+author+committer+message, an attacker who clones a public upstream repository tracked by Shipit under OrgB and pushes the identical commit history into their own repository under OrgA will produce byte-identical SHAs. When their own CI (or a hand-crafted signed request) emits a `status` event for OrgA's repo referencing that SHA, the request is genuinely signed with OrgA's real webhook secret and passes `verify_signature`, but `StatusHandler#process` matches and mutates OrgB's `Commit` row because the lookup is keyed only on `sha`.

`create_status_from_github!` creates a `Status`, which on create schedules continuous delivery for the owning stack: [4](#0-3) [5](#0-4) 

Test evidence confirms that a state transition to `pending`/`success` on a commit via this path enqueues `ProcessMergeRequestsJob` scoped to that commit's stack: [6](#0-5) 

The controller-level test for the `status` event also demonstrates the handler operates purely on `sha`, with the `repository` key in the payload used only for signature verification, never for scoping which commit gets updated: [7](#0-6) 

None of the existing guards close this gap: `verify_signature` authenticates the sender org but not the target commit's ownership; `drop_unhandled_event` and the `ExplicitParameters` schema in `StatusHandler` only type-check `sha`/`state`/etc.; there is no `force_github_authentication`, `User#authorized?`, or repository-ownership check anywhere in this handler.

### Impact Explanation
An attacker controlling any repository/org already configured in Shipit (with its own legitimate webhook secret) can forge a CI status onto an unrelated tenant's commit, provided a `Commit` row with a matching SHA exists (trivially achievable for any commit reachable in a public upstream repository, since re-pushing identical history yields identical SHAs). This can flip a victim stack's commit state to `success`/`pending`, enabling `enable_ci_on_stack` and triggering `ProcessMergeRequestsJob` against the victim's stack — i.e., a payload legitimately authenticated for OrgA mutates OrgB's commit/stack state and can influence OrgB's merge queue. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: the attacker's own organization/repository must already be a configured Shipit tenant with its own webhook secret (a real, if unprivileged, tenant of the multi-tenant Shipit instance — the question's stated precondition). Given that, no further privilege is needed: the attacker only needs a SHA that also exists as a `Commit` row for another stack, which is straightforward to obtain by mirroring any public repository Shipit already tracks. The attack is repeatable against any commit SHA the attacker can reproduce and against any number of victim stacks that happen to share that SHA.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the verified repository/organization, e.g. join through `Commit -> Stack -> Repository` and filter by `repository.owner`/`repository.full_name` derived from the same verified payload, rejecting or ignoring commits whose stack's repository owner does not match `repository_owner` used during signature verification.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/handlers/status_handler_test.rb` style):
1. Create `stack_org_b` owned by `Repository` with owner `"org-b"`, and a `Commit` fixture on it with `sha = "deadbeef..." `.
2. Stub/mock `Shipit.github(organization: "org-a").verify_webhook_signature` to return `true` (simulating a validly-signed request from OrgA), matching the existing pattern `GithubHook.any_instance.stubs(:verify_signature).returns(true)`.
3. POST a `status` webhook with `X-Github-Event: status`, body `{ sha: "deadbeef...", state: "success", repository: { owner: { login: "org-a" } } }`.
4. Assert the equality before: `repository_owner` from payload (`"org-a"`) != `commit.stack.repository.owner` (`"org-b"`).
5. Assert after processing: `commit.reload.statuses.count` increased and `commit.state == "success"` — proving OrgA's signed payload mutated OrgB's commit — and assert `ProcessMergeRequestsJob` was enqueued with `args: [stack_org_b]`, confirming the unauthorized merge-queue trigger on a tenant that never authenticated the request.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
