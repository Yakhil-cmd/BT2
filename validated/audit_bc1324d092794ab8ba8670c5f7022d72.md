### Title
`StatusHandler#process` writes GitHub Status updates by SHA alone, without validating the payload's repository against the target commit's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` selects commits via `Commit.where(sha: params.sha)` with no repository scoping, unlike the base `Handler#stacks` helper (used correctly by handlers such as `CheckSuiteHandler`) which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any records. Webhook signature verification is keyed off `repository_owner` derived from the payload's own `repository`/`organization` object, so it authenticates that the sender knows the secret for *their own* connected repository - it does not bind the payload's `repository` field to the SHA supplied in the body. As a result, an attacker who legitimately owns/administers a repository connected to Shipit can send a validly-signed `status` webhook whose `sha` value belongs to a commit tracked under a *different* repository's stack, and `StatusHandler` will write a `Status` row onto that unrelated stack's commit.

### Finding Description
The broken binding, stated as an equality that must hold but does not:

`repository_name_from_verified_payload (payload.dig('repository','full_name'), used only to select the HMAC secret in WebhooksController#verify_signature) == repository_scope_used_by_StatusHandler_to_select_Commit_rows (none - StatusHandler never reads payload.dig('repository', ...) or calls stacks)`

Trace:
- `Shipit::WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` and validates the HMAC using `repository_owner` taken from the payload's own `repository.owner.login` / `organization.login` [1](#0-0) [2](#0-1) . This proves only that the *sender* controls a repository/org connected to Shipit with a known secret - it says nothing about which stack the enclosed `sha` belongs to.
- `Handler#stacks` is the engine's intended repository-scoping primitive: `Repository.from_github_repo_name(repository_name)&.stacks`, with `repository_name` defined as `payload.dig('repository', 'full_name')` [3](#0-2) . `CheckSuiteHandler` correctly uses this: `stacks.where(branch: params.check_suite.head_branch).each { |stack| stack.commits.where(sha: ...) }` [4](#0-3) .
- `StatusHandler#process`, by contrast, does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . It never calls `stacks`, never reads `payload.dig('repository', 'full_name')`, and its `params` schema does not even require a `repository` field [6](#0-5) . `Commit` has no per-repository uniqueness constraint on `sha` (only `stack_id`+`sha` indexed, per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), so the same SHA can legitimately exist in multiple stacks, and `Commit.where(sha:)` is a global, unscoped query across every stack in the installation.

Exploit flow:
1. Attacker owns/administers `attacker-org/attacker-repo`, which they have connected to Shipit (or which otherwise has a webhook configured with a secret they know via the GitHub App/organization mapping the operator set up for that org).
2. Attacker learns (or already knows, since public repos expose commit SHAs) the SHA of a commit tracked in a victim stack, e.g., `victim-org/victim-repo`.
3. Attacker crafts a `status` event payload with `repository.full_name = "attacker-org/attacker-repo"` (so `verify_signature` validates against the secret they control) but `sha` = the victim commit's SHA, `state = "success"`, and POSTs it to `/webhooks`.
4. `verify_signature` passes because it only checks the sender's own repository/org secret. `StatusHandler#process` finds the victim's `Commit` by SHA (ignoring the `repository` field entirely) and calls `commit.create_status_from_github!(params)`, writing a forged Status onto the victim's commit.
5. This forged status can flip commit `state` and trigger `ProcessMergeRequestsJob` / affect deploy-readiness gating logic tied to required/blocking statuses in the victim stack (see `Status::Common#blocking?`/`required?`) [7](#0-6) , none of which the attacker owns or has any authorization over.

Why existing guards fail: `verify_signature` authenticates "who sent this" (bound to the sender's own org), not "which repository's records this payload is allowed to mutate." `drop_unhandled_event`, `ExplicitParameters` schema and `force_github_authentication` are irrelevant to this path (webhooks are unauthenticated HTTP, not session-based). No model validation constrains `Commit.sha` to be unique per stack in a way that would block this.

### Impact Explanation
An attacker with legitimate control of any single repository connected to Shipit can write forged CI `Status` rows (`success`/`failure`/`pending`, arbitrary `context`, `description`, `target_url`) onto commits belonging to **any other stack in the same Shipit installation**, without needing any access to that other repository. Since Status state feeds deploy-readiness/merge-gating logic (`ProcessMergeRequestsJob`, blocking/required statuses), this is a genuine any-repository-to-any-repository write that can manipulate whether a victim's commit is considered deployable/mergeable - matching the "payload for one repository mutating another's stack/commit" Critical category. The attack is repeatable indefinitely against any known SHA in any stack hosted by the installation.

### Likelihood Explanation
Preconditions: the attacker needs at least one repository connected to the target Shipit installation (i.e., under an org/App installation Shipit trusts) so they can produce a validly-signed webhook - a low bar for any developer who has a repo integrated with Shipit CI. They additionally need the target commit's SHA, which is trivially discoverable for any public repository, or for repositories they have any read access to. No Shipit session, API token, or GitHub App private key is required. This is a low-cost, easily repeatable attack once the attacker has any connected repository.

### Recommendation
Scope `StatusHandler#process` to the payload's own repository, mirroring `CheckSuiteHandler`: resolve the repository via `Repository.from_github_repo_name(repository_name)` (or `stacks`), and constrain the commit lookup to `stacks.flat_map(&:commits)`/`Commit.where(sha: params.sha, stack: stacks)` instead of the unscoped `Commit.where(sha: params.sha)`. Also require/validate a `repository.full_name` field in the `StatusHandler` params schema so a payload without repository context is rejected outright.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest)

test "StatusHandler does not scope to a resolved repository/stacks" do
  methods = Shipit::Webhooks::Handlers::StatusHandler.instance_methods(false) +
            Shipit::Webhooks::Handlers::StatusHandler.private_instance_methods(false)
  refute_includes methods, :stacks
  refute_includes methods, :repository_name
end

test "a status payload for repo A writes a Status onto a commit belonging to stack of repo B" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)
  victim_commit.update!(sha: 'deadbeef' * 5)

  attacker_repo_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'forged/ci',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo' }
  }

  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # simulate attacker's own valid secret

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: attacker_repo_payload.to_json, as: :json,
         headers: { 'X-Github-Event' => 'status' }
  end
  # Demonstrates the equality repository_name(payload) == repository_scope(commit selection) is absent:
  # the payload names attacker-org/attacker-repo, yet the mutated commit belongs to victim's stack.
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
