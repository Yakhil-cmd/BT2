## Title
Cross-tenant Status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` only proves that the request body was signed by *some* onboarded GitHub organization's `webhook_secret`, using `repository_owner` read straight from `params.dig('repository','owner','login')`. `StatusHandler#process` then looks up commits with `Commit.where(sha: params.sha)` globally, without any check that the commit's `stack`/`repository` matches the organization that produced the valid signature, allowing any onboarded org to write `Status` rows onto another tenant's commits.

### Finding Description
The broken binding is: `organization_that_signed_the_request == organization_owning_the_commit_being_mutated`. In `WebhooksController#verify_signature`, the app resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . This only confirms the HMAC in `X-Hub-Signature` matches the `webhook_secret` for whatever org string is embedded in the JSON body — the attacker fully controls this string and can set it to their own onboarded org to pass verification.

`StatusHandler#process`, unlike `CheckSuiteHandler` (which scopes via `stacks.where(branch: ...)` derived from `Repository.from_github_repo_name(repository_name)` [3](#0-2) [4](#0-3) ), does not use the `stacks`/`repository_name` scoping helper at all:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This queries the entire `commits` table by `sha` with no `repository`/`stack` filter, so any commit anywhere in the Shipit instance matching that SHA gets a new `Status` regardless of which organization's payload envelope it arrived in.

Exploit flow: an attacker registers/owns a GitHub org "attacker-org" that is legitimately onboarded to this Shipit instance (has a configured `webhook_secret`). They observe or otherwise learn a commit SHA belonging to a foreign tenant's stack (e.g., a public repo commit under "victim-org"). They POST to `/webhooks` with header `X-Github-Event: status`, a valid signature computed with their own `webhook_secret`, and a JSON body:
```json
{"sha": "<victim commit sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}}}
```
`verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and verifies successfully since the attacker signed correctly with their own secret [1](#0-0) . `StatusHandler#process` then finds the victim's `Commit` row purely by `sha` and calls `commit.create_status_from_github!(params)`, writing an attacker-controlled `state`/`description`/`target_url` onto the victim's commit [6](#0-5) .

Existing tests confirm this exact behavior is the intended/expected flow rather than an oversight caught by tests: `":state create a Status for the specific commit"` merges `repository_params` (`{owner: {login: 'shopify'}}`) purely to pass signature verification, and the handler locates the commit by SHA alone [7](#0-6) . No test asserts that the `repository.full_name` in the payload matches the commit's actual stack/repository.

None of the listed guards prevent this: `verify_signature`/`GitHubApp#verify_webhook_signature` only check the HMAC against the org name embedded in the attacker's own payload [8](#0-7) ; `drop_unhandled_event` only checks event type is handled; the `ExplicitParameters` schema in `StatusHandler` only validates types/presence of `sha`/`state`/etc, not ownership [9](#0-8) ; and `StatusHandler` never calls the `stacks`/`repository_name` helper that other handlers use for scoping.

### Impact Explanation
An attacker who controls one legitimately onboarded GitHub organization can write forged commit `Status` rows (state/description/target_url/context/created_at) onto any commit SHA belonging to any other tenant's stack in the same Shipit instance, as long as that SHA is already present in the `commits` table (synced via prior push/PR webhooks or GithubSync). Since `Status` records influence whether a commit is considered "green"/mergeable/deployable (`required_statuses`, `blocking_statuses` in `Commit`) [10](#0-9) , this can be used to falsely mark a foreign tenant's commit as `success`, potentially unblocking merges/deploys for a stack the attacker does not own — a payload for one repository mutating another's commit/stack state. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is fully repeatable against any commit SHA in any onboarded tenant's history.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multiple GitHub organizations (`Shipit.github(organization: ...)` supporting a hash of orgs, as documented for "Using Multiple Github Applications") and the attacker must control (own or compromise) at least one such onboarded org so they possess a valid `webhook_secret` to sign with — a low-cost precondition satisfiable by simply getting onto a shared Shipit instance used by multiple organizations. The victim's commit SHA needs to be known, which is trivial for public repositories. No GitHub App private key, session, or Shipit credentials are required beyond the attacker's own org's webhook secret. This is a single unauthenticated-adjacent HTTP POST, fully repeatable.

### Recommendation
In `StatusHandler#process` (and any other handler using raw model lookups by SHA/ID), scope the query to the repository declared in the payload the same way `CheckSuiteHandler` does, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`, using the `Handler#stacks`/`repository_name` helper so that only commits belonging to the repository actually named in the signed payload are mutated. Additionally, consider validating that `repository_owner` used for signature verification matches the actual owner associated with `repository.full_name`, to prevent an attacker from picking any owner string independent of the mutated repository.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":status cross-tenant forgery writes Status on a foreign stack's commit" do
  # victim commit belongs to shipit_stacks(:shipit) / a different org than attacker
  victim_commit = shipit_commits(:first)
  attacker_owner_login = 'attacker-org'

  request.headers['X-Github-Event'] = 'status'
  Shipit.stubs(:github).with(organization: attacker_owner_login).returns(
    stub(verify_webhook_signature: true)
  )

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => attacker_owner_login }, 'full_name' => 'attacker-org/unrelated-repo' }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: body, as: :json
  end
  # Binding check: organization that signed (attacker_owner_login) != organization owning victim_commit.stack
  assert_not_equal attacker_owner_login, victim_commit.stack.repository.owner
end
```
This demonstrates that despite the signing organization (`attacker-org`) having no relationship to the victim stack's repository, `StatusHandler#process`'s unscoped `Commit.where(sha: ...)` lookup still creates a `Status` on the victim's commit.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
