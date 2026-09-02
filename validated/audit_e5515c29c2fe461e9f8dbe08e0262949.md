### Title
Webhook auth-org / target-repo binding break: `repository_owner` (used to select the HMAC key) is independent from `repository.full_name` (used by `Handler#repository_name`/`Handler#stacks`), letting a payload "authenticated" under one org mutate another org's stacks - (File: `app/models/shipit/webhooks/handlers/handler.rb`, `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret using `repository_owner = payload.dig('repository','owner','login') || payload.dig('organization','login')`, while `Handler#repository_name`/`Handler#stacks` independently read `payload.dig('repository','full_name')` to locate the `Repository`/`Stack` rows to mutate. Because these two lookups read different, attacker-controlled JSON keys with no cross-validation, an attacker can pick an organization whose GitHub App config has no `webhook_secret` set (which makes `GitHubApp#verify_webhook_signature` trivially return `true`), while pointing `repository.full_name` at a real victim repository, causing the handler to mutate the victim's `Stack`/`Commit` rows.

### Finding Description
Broken binding: `organization_that_authenticated(payload) == organization_owning(Handler#stacks(payload))` is expected to hold but does not.

- `verify_signature` computes the signing org from `repository.owner.login` with a fallback to `organization.login`: [1](#0-0)  and [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that org: [3](#0-2) .
- `Handler#repository_name` and `Handler#stacks` read `repository.full_name` from the same payload, completely independent of whichever org key was used to verify the signature: [4](#0-3) .
- Handlers such as `PushHandler` and `CheckSuiteHandler` use `stacks` (derived from `repository.full_name`) to mutate real `Stack`/`Commit` records: [5](#0-4) [6](#0-5) .

Attacker request: send `POST /webhooks` with header `X-Github-Event: push` (or `check_suite`), and body:
```json
{
  "repository": { "full_name": "victim-org/victim-repo" },
  "organization": { "login": "org-with-no-secret" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
Because `repository.owner.login` is absent, `repository_owner` falls back to `organization.login` = `"org-with-no-secret"`. If that org is configured in Shipit (`Shipit.github(organization: "org-with-no-secret")` resolves without raising `GithubOrganizationUnknown`) and its config has a blank `webhook_secret`, `verify_webhook_signature` returns `true` for any/no signature. `WebhooksController#create` then calls `PushHandler.call(params)`, whose `stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` - a real record unrelated to `"org-with-no-secret"` - and enqueues `GithubSyncJob`/mutates the victim's `Stack`.

None of the existing guards close this gap: `drop_unhandled_event` only checks event type; the `ExplicitParameters` schemas (`requires :ref`, `requires :after`, etc.) validate presence/type but never cross-check `repository.owner.login`/`organization.login` against `repository.full_name`; `Repository.from_github_repo_name` performs no ownership check tied to the authenticated org [7](#0-6) .

### Impact Explanation
Any handler relying on `Handler#stacks`/`repository_name` (`PushHandler`, `CheckSuiteHandler`, and any future handler using the same base method) can be made to enqueue sync jobs, create/refresh commits, or trigger check-run refreshes against a completely different, real repository's `Stack`/`Commit` rows, using a signature that was only valid for an unrelated, attacker-chosen organization. This matches the "Critical" category: a payload for one repository mutating another's stack/commit records. The attack is repeatable against any onboarded repository whose `full_name` the attacker knows (repository names are not secret), for as long as the misconfigured no-secret org config remains active.

### Likelihood Explanation
This requires a specific Shipit deployment precondition: a multi-organization GitHub App configuration (`github_default_organization` present) where at least one configured organization has no `webhook_secret` set, so `verify_webhook_signature` trivially returns `true` for that org's traffic [8](#0-7) . This is an explicitly supported code path (not a crash/edge case), plausible in real deployments (e.g., staging/sandbox orgs, or an org mid-onboarding before its secret is set). Given that precondition, the attacker's cost is a single unauthenticated HTTP POST with no secrets, teams, or sessions required, and the attack is trivially repeatable against arbitrary victim stacks.

### Recommendation
Make the organization used to select the signing key and the organization implied by the target repository the same, verified value:
- In `WebhooksController#verify_signature`, derive `repository_owner` strictly from `repository.full_name`'s owner segment (or require `repository.owner.login` to equal the owner parsed from `repository.full_name`), and reject the request if they diverge.
- In `Handler#stacks`, after resolving the `Repository`, assert its `owner` matches the org that was used to authenticate the request (pass the verified org down to the handler, or re-derive `repository_owner` inside the handler and compare it to `Repository#owner`).
- Consider making `webhook_secret` mandatory for every configured organization (fail closed instead of `return true unless webhook_secret`).

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (illustrative; requires Shipit test config with two orgs, one lacking `webhook_secret`, e.g. `no-secret-org`, plus an existing `shipit_stacks(:shipit)` owned by a different org, e.g. `shopify`):

```ruby
test "payload authenticated by org A can mutate org B's stack" do
  victim_stack = shipit_stacks(:shipit) # owned by 'shopify'
  request.headers['X-Github-Event'] = 'push'

  payload = {
    'ref' => "refs/heads/#{victim_stack.branch}",
    'after' => 'deadbeef',
    'repository' => { 'full_name' => victim_stack.repo_name }, # no 'owner' key
    'organization' => { 'login' => 'no-secret-org' } # configured with blank webhook_secret
  }.to_json

  # left side of the equality: org that authenticated the bytes
  assert_equal 'no-secret-org',
    JSON.parse(payload).dig('organization', 'login')

  # right side of the equality: org owning the stacks Handler#stacks returns
  assert_equal 'shopify', victim_stack.repository.owner

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef']) do
    post :create, body: payload, as: :json
  end
  assert_response :ok
end
```
This asserts the divergence exists (`"no-secret-org" != "shopify"`) and that, despite this, `GithubSyncJob` is enqueued for `victim_stack`, demonstrating the cross-org mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
