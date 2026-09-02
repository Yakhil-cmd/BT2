### Title
Repository-agnostic `Commit` lookup in `StatusHandler#process` allows an authenticated attacker-org webhook to mutate victim-org commit status - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` correctly scopes signature verification to the organization named in `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) , but `StatusHandler#process` never checks that the matched `Commit` actually belongs to a repository owned by that authenticated organization. It looks up commits solely by `sha` across the entire `commits` table and mutates whatever it finds. [3](#0-2) 

### Finding Description
Binding claimed: `repository_owner` (the org whose `webhook_secret` produced a valid `X-Hub-Signature`) == owner of every `Commit`/`Stack` mutated by the handler invoked with that payload. Tracing the code shows this does not hold.

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`, authenticating only that the *body* was signed with *that organization's* secret. [1](#0-0) 
- `#create` then parses the body and dispatches to handlers for the event with `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` — the org context established by `verify_signature` is not passed into the handler and is not re-checked. [4](#0-3) 
- `StatusHandler#process` performs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a global, repository-agnostic lookup on `sha` with no filter on `stack.repository.owner` or `full_name`. [3](#0-2) 
- `create_status_from_github!` then writes a new `Status`/`CommitStatus` tied to `stack_id` (`statuses.replicate_from_github!(stack_id, github_status)`), and can enqueue downstream side effects such as `ProcessMergeRequestsJob`/`deployable_status` hooks against whichever `stack` owns that commit — a stack that could belong to victim-org, not attacker-org. [5](#0-4) 

Attacker request: a valid GitHub status webhook delivery from `attacker-org`'s own repository/app (correctly signed with `attacker-org`'s real `webhook_secret`), with `repository.owner.login = "attacker-org"` and a `sha` value equal to a `sha` that exists on a victim-org `Commit` row (e.g. because both orgs happen to reference the same commit sha — trivially achievable if the attacker forks/mirrors the victim's repo and pushes/tags the exact same commit, or simply because CI systems commonly send identical SHAs across mirrored repos). Because `Commit.where(sha:)` is not scoped by repository or stack, the handler updates the victim's `Commit` status regardless of which org's key was used to authenticate the request.

None of the existing guards address this: `verify_signature` only authenticates the payload against a secret, not which rows the handler is permitted to touch; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema (`params do ... end` in `StatusHandler`) only validates presence/type of `sha`/`state`/etc., not ownership; there is no `force_github_authentication`, `require_permission!`, or `stacks` scope invoked anywhere in this controller/handler path. [6](#0-5) 

### Impact Explanation
An attacker who controls only their own GitHub org/repo webhook secret can write GitHub status entries (`Status`/CI state) onto a **victim organization's** commit, provided the commit `sha` matches. This can flip a victim commit's CI state (e.g., to `success`), which can unblock/trigger deploy eligibility (`deployable?` checks `success? && !blocked?`) and enqueue `ProcessMergeRequestsJob` against the victim's stack, per the transition test in `commits_test.rb`. This is a cross-tenant write into another repository's commit/stack state despite a fully valid, non-forged signature check — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." [3](#0-2) [7](#0-6) 

### Likelihood Explanation
Requires only that attacker-org has a Shipit-configured GitHub App/webhook (a legitimate, unprivileged setup any org integrating with Shipit would have) and that a `sha` collision exists between an attacker-controlled repo and a targeted victim repo's commit — trivially arranged by mirroring/forking the victim repo so identical commits (identical SHA) exist in both, then firing a `status` event from the attacker's own repo. No secrets, tokens, or privileged roles of the victim are needed; the attack is repeatable against any commit sha the attacker can reproduce in their own repository.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing bare `Commit.where(sha:)`/similar lookups) to only mutate commits whose `stack.repository.owner` (or `full_name`) matches the authenticated `repository_owner`/`repository.full_name` from the webhook payload, e.g. `Commit.joins(:stack).merge(Stack.where(repository: ...)).where(sha: params.sha)`, and pass the verified repository context from the controller into `Webhooks.for_event(event).each { |handler| handler.call(params, verified_repository:) }` so handlers can enforce it explicitly.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `victim_stack`/`victim_commit` fixture with `sha = "deadbeef..."` under `repository.owner.login = "victim-org"`.
2. Stub `Shipit::GitHubApp#verify_webhook_signature` to return `true` only when called in the context of `attacker-org` (or stub `Shipit.github(organization: "attacker-org")` to return a fake app whose `verify_webhook_signature` always returns true).
3. POST to `/webhooks` with header `X-Github-Event: status`, body `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "deadbeef...", "state": "success", "context": "ci/attacker"}`.
4. Before request: assert `victim_commit.reload.state != "success"`.
5. After request: assert `victim_commit.reload.state == "success"` (or assert `Status.where(commit: victim_commit, context: "ci/attacker").exists?`), proving that `repository_owner` (`"attacker-org"`, authenticated) != owner of the mutated commit's stack (`"victim-org"`), while the request still returned `200 OK`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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
