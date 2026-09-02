### Title
Divergent `repository_owner` (signature verifier selector) vs `repository.full_name` (stack selector) lets a forged `check_suite` webhook, verified through an org with no `webhook_secret`, act on an unrelated repository's stack - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/check_suite_handler.rb`)

### Summary
`Shipit::WebhooksController#repository_owner` picks the `GitHubApp` used to verify `X-Hub-Signature` from `repository.owner.login`, falling back to `organization.login` when the former is absent, while `Shipit::Webhooks::Handlers::Handler#repository_name` (used by `CheckSuiteHandler`) independently reads `repository.full_name` from the raw payload. Because these two fields can be set independently by the attacker within the same JSON body, an attacker can route signature verification through an organization configured without a `webhook_secret` (which unconditionally passes verification) while pointing `repository.full_name` at a completely different, victim-owned stack.

### Finding Description
The intended invariant is: `repository_owner used for verification == owner(repository.full_name used by the handler)`, i.e. the org whose secret authenticated the request should be the org whose repository/stack is acted upon.

Code path:
- `Shipit::WebhooksController#verify_signature` selects the verifier with:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [2](#0-1) 

- `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the resolved org has no configured `webhook_secret`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [3](#0-2) 

- `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` reads a *different* field, directly from the raw payload, bypassing `ExplicitParameters` schema entirely:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

- `CheckSuiteHandler`'s param schema only requires `check_suite.head_sha`/`head_branch`; it never requires or validates `repository`, so `repository.owner.login` and `repository.full_name` are both fully attacker-controlled and unconstrained relative to each other:
```ruby
params do
  requires :check_suite do
    requires :head_sha, String
    requires :head_branch, String
  end
end
def process
  stacks.where(branch: params.check_suite.head_branch).each do |stack|
    stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
  end
end
``` [5](#0-4) 

Exploit request: the attacker POSTs to `/webhooks` with header `X-Github-Event: check_suite` and a body such as:
```json
{
  "check_suite": {"head_sha": "<victim commit sha>", "head_branch": "<victim stack branch>"},
  "repository": {"full_name": "victim-org/victim-repo"},
  "organization": {"login": "org-without-secret"}
}
```
Here `repository.owner.login` is omitted (only `full_name` is set), so `repository_owner` falls back to `organization.login` = `org-without-secret`. If `org-without-secret` is a configured Shipit org lacking `webhook_secret` (per `GitHubApp#initialize`, `@webhook_secret = @config[:webhook_secret].presence`) [6](#0-5)  then `verify_webhook_signature` returns `true` regardless of signature/header content, and the request is accepted. The handler then resolves the target stack purely from `repository.full_name = "victim-org/victim-repo"`, entirely independent of the org that "authenticated" the request, and calls `schedule_refresh_check_runs!` on matching commits of the victim's stack.

Existing guards do not catch this: `drop_unhandled_event` only checks the event is registered [7](#0-6) ; `ExplicitParameters` for `CheckSuiteHandler` never requires `repository` at all, so no schema validation ties `repository.full_name` to `repository_owner`; and `Repository.from_github_repo_name` performs no ownership/secret cross-check against the org used for verification.

### Impact Explanation
An unprivileged, unauthenticated attacker can cause a webhook payload that is "authenticated" against one (secret-less) organization to mutate/act on the state of a stack belonging to a completely different, properly-secured organization/repository — precisely the "payload for one repository mutating another's stack" and "forged webhook accepted as trusted" categories called out as Critical. The concrete effect here is forcing `Commit#schedule_refresh_check_runs!` to run for arbitrary matching commits/stacks system-wide, without ever needing to know or supply the victim repository's real `webhook_secret`. This is repeatable against every stack in the Shipit instance as long as one org without a `webhook_secret` exists (a documented pattern e.g. for enterprise/self-hosted GitHub setups where secrets aren't configured), giving cross-tenant blast radius across the whole application.

### Likelihood Explanation
Preconditions: at least one organization must be configured in Shipit without a `webhook_secret` (the question's stated scenario), and the attacker only needs to know a target stack's `branch` and a `head_sha` of an existing commit on that stack (both discoverable from public GitHub repository data or the Shipit UI/API for public stacks). The attacker needs no session, token, or secret. The attack is a single unauthenticated HTTP POST, fully scriptable and repeatable at will.

### Recommendation
Derive the repository/stack used by every webhook handler from the same field(s) used to select the verifying `GitHubApp`, and reject the request if `repository.owner.login` (or `organization.login`) does not match the owner implied by `repository.full_name`. Additionally, require `repository.full_name` in `CheckSuiteHandler`'s (and the base `Handler`'s) `ExplicitParameters` schema rather than reading it ad hoc from `payload.dig`, and treat a missing/empty `webhook_secret` for a configured org as a configuration error to reject (fail closed) rather than silently trusting all payloads for that org.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (or a new test) under a section mirroring "organization fallback selection":
```ruby
test "check_suite: org without webhook_secret allows forging events targeting another repository's stack" do
  # victim stack belongs to a different, secret-protected org
  victim_stack = shipit_stacks(:shipit) # e.g. github_repo_name == "shopify/shipit-engine"
  commit = victim_stack.commits.last

  # attacker-chosen org configured WITHOUT webhook_secret
  Shipit.stubs(:github).with(organization: 'org-without-secret').returns(
    Shipit::GitHubApp.new('org-without-secret', {}) # no :webhook_secret key => verify returns true unconditionally
  )

  body = {
    check_suite: { head_sha: commit.sha, head_branch: victim_stack.branch },
    repository: { full_name: victim_stack.github_repo_name }, # no owner.login key
    organization: { login: 'org-without-secret' }
  }.to_json

  request.headers['X-Github-Event'] = 'check_suite'
  # no valid X-Hub-Signature for victim_stack's real secret is supplied

  assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit_id: commit.id]) do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
Assert both sides of the binding explicitly before/after: `repository_owner` (`== 'org-without-secret'`) must differ from `victim_stack.repository.owner` (`== 'shopify'`), and yet `RefreshCheckRunsJob` is enqueued for `commit` belonging to `victim_stack` — demonstrating the authentication/authorization divergence.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L7-17)
```ruby
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
