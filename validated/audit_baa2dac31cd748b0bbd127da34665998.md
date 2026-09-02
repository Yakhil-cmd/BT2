### Title
Webhook signature verification checks `repository.owner.login` but handlers mutate the repository named by `repository.full_name`, allowing cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization secret to verify against using `repository.owner.login` (or `organization.login`) from the request body, but `Shipit::Webhooks::Handlers::Handler#stacks` (used by `PushHandler` and `CheckSuiteHandler`) resolves the target repository using the separate `repository.full_name` field from the same body. Since these two fields are never cross-validated, an attacker who controls a webhook_secret for their own repository can forge a payload where `owner.login` names their own org (so verification succeeds) while `full_name` names a victim's repository, causing the handler to mutate the victim's `Stack`/`Commit` rows.

### Finding Description
The broken binding is: `organization_that_signed(repository.owner.login)` MUST equal `organization_owning(repository.full_name)`. This is never enforced.

- `WebhooksController#verify_signature` picks the verifying app/secret via `repository_owner`, derived only from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and verifies the HMAC using `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 

- Once signature verification passes, `Handler#stacks` (used as the base for `PushHandler` and `CheckSuiteHandler`) resolves the target repository via `repository_name`, which reads a *different* field of the same top-level `repository` object: `payload.dig('repository', 'full_name')`. [3](#0-2) 

- `PushHandler#process` uses `stacks` to find and mutate stacks/commits for whatever repository `full_name` names, calling `stack.sync_github(...)`. [4](#0-3) 

- `CheckSuiteHandler#process` similarly uses `stacks` (i.e., `full_name`) to locate and mutate a victim stack's commits, scheduling check-run refreshes. [5](#0-4) 

Exploit flow: The attacker owns `attacker-org/attacker-repo` and configures/controls its GitHub App webhook (thus knows the `webhook_secret` bound to `attacker-org`). They send `POST /webhooks` with header `X-Github-Event: push`, body signed correctly against `attacker-org`'s secret, but with body content:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
`verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and verifies successfully because the attacker signed with their own secret. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and issues `sync_github` calls against the victim's stacks — an unauthenticated cross-tenant mutation.

None of the existing guards catch this: `verify_signature` only checks the HMAC against the org named by `owner.login`, never checking it against the org implied by `full_name`; `drop_unhandled_event` only filters by event type, not payload content; the `ExplicitParameters` schemas for `PushHandler`/`CheckSuiteHandler` only require the presence/type of `ref`/`after` or `check_suite.head_sha`/`head_branch`, not that `repository.full_name`'s owner segment matches `repository.owner.login`; and `Repository#owner`/`#name` format validators only constrain characters, not provenance.

### Impact Explanation
An attacker who owns any repository with GitHub App webhook integration (fully under their control) can trigger `GithubSyncJob`-driven syncs (`PushHandler`) or `schedule_refresh_check_runs!` (`CheckSuiteHandler`) against an arbitrary victim `Stack`/`Commit`, keyed purely by a string they place in `repository.full_name`, with no relationship to the org that actually signed the payload. This is a payload for one (attacker-controlled) repository mutating another (victim) repository's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team"). The attack is repeatable against any repository name known to the attacker (repository names are public / discoverable), across all tenants configured in this Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must operate their own GitHub organization/repository with a Shipit-configured GitHub App installation (or otherwise obtain any valid `webhook_secret` for any org registered in `Shipit.github_teams`/config) — something explicitly available to "any GitHub user who can open a pull request... and emit webhooks from a repository they own" per the threat model. No Shipit session, API token, or victim-owned secret is required. The cost is a single crafted HTTP POST with a body they control end-to-end (they know their own `webhook_secret`), making this trivially repeatable and low-cost.

### Recommendation
Bind the verified organization to the mutated repository. In `WebhooksController` (or in `Handler`), after signature verification, ensure the org used to derive `repository_owner` for signing matches the owner segment of the repository actually referenced during processing (e.g., pass the verified `repository_owner` into handler construction and have `Handler#repository_name`/`#stacks` assert `payload.dig('repository', 'full_name').downcase.start_with?("#{repository_owner}/")`, or simply derive `repository_name` from `owner.login` + a separate `repository.name` field consistently, rather than trusting the independent `full_name` string). Reject/drop the webhook if the two disagree.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb

test "push payload naming a different repo's full_name than the verified owner does not mutate victim stack" do
  attacker_owner = "attacker-org"
  victim_stack = shipit_stacks(:shipit) # owner: 'shopify', name: 'shipit-engine' fixture, e.g.

  Shipit.github(organization: attacker_owner).stubs(:verify_webhook_signature).returns(true)

  @request.headers['X-Github-Event'] = 'push'
  body = {
    ref: 'refs/heads/master',
    after: 'deadbeef',
    repository: {
      owner: { login: attacker_owner },
      full_name: victim_stack.repository.github_repo_name
    }
  }.to_json

  assert_no_enqueued_jobs(only: GithubSyncJob) do
    post :create, body: body, as: :json
  end
  assert_response :ok
end
```
Before the fix: the job IS enqueued against `victim_stack.id` (mutation succeeds despite the signature having been verified only against `attacker-org`'s secret) — demonstrating `organization_that_signed != organization_owning(full_name)` yet the write proceeds. After the fix, the request should be rejected/dropped, and the assertion of "no enqueued job" should pass.

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
