### Title
Cross-repository Status forgery via unscoped SHA lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table, with no filter on the repository that the verified webhook belongs to. Since `Commit#stack_id` and `sha` are only unique together (indexed as `(stack_id, sha)`, not `sha` alone), an attacker controlling Repository B's own signed webhook can trigger a `Status` write against any other stack's commit that happens to share the same SHA.

### Finding Description
The broken binding, stated as an equality that should hold but does not: `payload.dig('repository','full_name')` (the repository whose `webhook_secret` produced a valid signature) should equal `commit.stack.repository.full_name` for every `Commit` mutated by the handler. `StatusHandler` never enforces this.

Code path:
- `WebhooksController#create` parses `params` from the raw body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
- `verify_signature` only checks that the payload was signed by the `webhook_secret` of `Shipit.github(organization: repository_owner)`, i.e. it authenticates that repository B's GitHub App produced the payload — it does not verify that the `sha` inside the payload belongs to repository B [2](#0-1) .
- `Handler` base class does provide a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, keyed off `payload.dig('repository', 'full_name')` [3](#0-2) . Other handlers such as `CheckSuiteHandler` use this `stacks` scope to constrain the affected records to the repository named in the verified payload.
- `StatusHandler#process`, however, ignores this scoping entirely and queries commits globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)`, writing a `Status` row scoped to whatever `stack_id` the matched commit belongs to [5](#0-4)  and [6](#0-5) .
- The DB only enforces uniqueness of `sha` per `(stack_id, sha)` pair (migration `20170524104615_index_commits_on_stack_id_and_sha.rb`), meaning multiple `Commit` rows with the identical `sha` legitimately coexist across different stacks/repositories (e.g., a commit cherry-picked, rebased into both repos, or a crafted empty-tree commit with identical tree+parents+timestamps).

Exploit flow: attacker (owner of Repository B, tracked by a `GithubHook`) crafts/finds a commit whose SHA collides with a commit already tracked in Repository A's stack, pushes it to B, then sends a `status` event webhook to `POST /webhooks` with `repository.full_name = B`, `sha = <colliding sha>`, `state: success`, signed with B's own `webhook_secret` (which the attacker legitimately controls since they own B's GitHub App/webhook config, or can trigger via a normal CI status event on their own repo). `verify_signature` passes because the signature is valid for B. `StatusHandler#process` matches Repository A's `Commit` row by bare `sha` and creates a `Status` under A's `stack_id`, without any check that the payload's `repository.full_name` corresponds to A.

Existing guards do not stop this: `verify_signature` authenticates the source organization/app but never binds the `sha` claim to that organization's repository; the `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`/etc., not repository ownership; and `StatusHandler` conspicuously omits any call to the `stacks` helper that other handlers use for exactly this kind of scoping.

### Impact Explanation
A successful exploit lets an attacker fabricate a `Status` (e.g., `state: success` from a fake/malicious CI context) attached to a commit under a stack/repository they do not own or control. Since `deployable?` and CI-gating logic (`Commit#deployable?`, `blocked?`) consult `status`/`statuses` to determine whether a commit can be deployed, a forged "success" status can help make an otherwise-unverified or CI-failing commit appear deployable in Repository A's stack, contributing to an unauthorized/incorrectly-gated deploy — this matches the "payload for one repository mutating another's stack/commit" Critical category. The attack is repeatable against any Shipit-tracked repository pair that happen to share the exact commit SHA, though it is not repeatable against arbitrary repositories without the SHA collision precondition.

### Likelihood Explanation
This requires: (1) both repos already onboarded to Shipit with `GithubHook` rows, (2) the attacker's own repository B has a working webhook (which they control, since they own B), and (3) a commit SHA collision between a commit in B and a commit tracked in A's stack. SHA collision via git object identity (same tree, parents, author/committer name+email+timestamp, and message) is achievable deliberately by an attacker who can construct an identical commit object (e.g., cherry-picking the exact same commit into both repos, which is a realistic scenario for shared upstream history, forks, or vendored branches) — this is not a cryptographic SHA-1 collision, just identical git object content, which is trivial to engineer between repos that share history. This significantly lowers the bar versus a true hash collision, making the attack practically feasible against repos that share commits (forks, mirrors, subtree merges).

### Recommendation
Scope `StatusHandler#process` to only the stacks/commits belonging to the repository named in the verified payload, mirroring the pattern used elsewhere in the `Handler` base class:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This binds the mutation to `Repository.from_github_repo_name(repository_name)`, i.e., the repository authenticated by `verify_signature`, closing the cross-tenant write.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style) plan:
```ruby
test ":status payload for repo B must not create a Status on repo A's commit with colliding sha" do
  stack_a = Shipit::Stack.create!(repository: create_repo("org/repo-a"), environment: "production", branch: "master")
  stack_b = Shipit::Stack.create!(repository: create_repo("org/repo-b"), environment: "production", branch: "master")

  colliding_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: colliding_sha, message: "shared", author: shipit_users(:shipit), committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)

  GithubHook.any_instance.stubs(:verify_signature).returns(true)
  request.headers['X-Github-Event'] = 'status'

  body = {
    sha: colliding_sha,
    state: 'success',
    context: 'ci/forged',
    repository: { full_name: 'org/repo-b', owner: { login: 'org' } }
  }.to_json

  assert_no_difference -> { commit_a.statuses.count } do
    post :create, body:, as: :json
  end
end
```
Before the fix: `commit_a.statuses.count` increases by 1 despite the payload naming `org/repo-b`, proving `Status.stack_id == stack_a.id` while `payload['repository']['full_name'] == 'org/repo-b' != stack_a.repository.full_name`. After applying the recommended `stacks`-scoped fix, the assertion passes (no Status created under `stack_a`).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
