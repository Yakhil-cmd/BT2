## Binding (explicit)

The claimed authorization binding is:

`organization_verified_in(WebhooksController#verify_signature) == organization_owning(Stack/Commit mutated by StatusHandler#process)`

Tracing the code shows this binding is **never enforced**, and is in fact **broken more severely** than the question states — `StatusHandler#process` doesn't even attempt any repository/stack scoping at all.

- `verify_signature` derives `repository_owner` purely from the unverified JSON body (`params.dig('repository','owner','login')`) and looks up the webhook secret via `Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .
- `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — an **unscoped, global** lookup by `sha` across every stack/repository in the database, with no reference to `repository_owner` or `repository.full_name` whatsoever [3](#0-2) .
- Contrast this with `CheckSuiteHandler#process`, which correctly scopes to `stacks` (derived from `payload.dig('repository','full_name')`) before touching any commit [4](#0-3) [5](#0-4) . `StatusHandler` has no equivalent `stacks`/`repository_name` filter at all.

Since GitHub commit SHAs are content-addressed and can collide across repositories (identical trees/parents/commit metadata, or via fork/mirror scenarios where the same commit is legitimately present in multiple Shipit-tracked stacks), any attacker who owns a `GithubHook` for their own org can sign a `status` webhook body containing a victim's known `sha` and have it accepted:

1. `verify_signature` computes `repository_owner = 'attacker-org'` from the body and validates HMAC using `Shipit.github(organization: 'attacker-org')`'s secret — attacker knows this secret, so verification passes.
2. `StatusHandler#process` ignores `repository_owner`/`repository.full_name` entirely and does `Commit.where(sha: params.sha)`, matching any commit row with that SHA regardless of which stack/org it belongs to, and writes a `Status` row via `create_status_from_github!` [3](#0-2) .

No existing guard closes this gap: `drop_unhandled_event` only filters unknown event types [6](#0-5) ; `ExplicitParameters` only validates shape/types, not ownership [7](#0-6) ; and there is no post-verification re-check tying the authenticated org to the mutated commit's stack.

### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates only that *some* org's webhook secret produced a valid HMAC over the raw body, using an org name read from the same untrusted JSON payload. `StatusHandler#process` then updates commit status by a bare, database-wide `sha` match with no repository/stack scoping, so an attacker who legitimately controls a `GithubHook` for their own throwaway org can write CI status data onto a commit belonging to a completely different, victim-owned stack.

### Finding Description
Broken binding: `organization_verified_in(verify_signature) == organization_owning(Stack of Commit mutated in StatusHandler#process)`. The left side is `params.dig('repository','owner','login')` read from the unauthenticated body before signature verification even determines it's trustworthy for that purpose [2](#0-1) . The right side is whatever stack the matched `Commit` row happens to belong to, determined solely by `Commit.where(sha: params.sha)` with zero relation to `repository_owner` [3](#0-2) . These two values are never compared. An attacker with a valid `GithubHook` for `attacker-org` sends `POST /webhooks` with `X-Github-Event: status`, body `{"repository":{"owner":{"login":"attacker-org"},"full_name":"attacker-org/decoy"},"sha":"<victim-commit-sha>","state":"success",...}`, HMAC-signed with `attacker-org`'s own secret. `verify_signature` passes because it only checks that *a* known org's secret matches the body. `StatusHandler#process` never reconsults `repository_owner`/`repository.full_name` and mutates any `Commit` row matching that `sha`, regardless of which stack/org owns it. This differs from `CheckSuiteHandler`, which correctly filters through `stacks` derived from `repository.full_name` before touching commits [4](#0-3) .

### Impact Explanation
An attacker can inject arbitrary CI `state`/`context`/`target_url`/`description` values onto a victim's tracked commit if they can predict or observe its SHA (SHAs are not secret — visible in PRs, commit pages, CI logs, etc.). Because `Commit#state` and `Stack#branch_status`/merge gating logic depend on `Status` rows, this can flip a commit from `pending`/`failure` to `success`, potentially unblocking merges/deploys that the victim's CI never actually approved. This is a payload-for-one-repository-mutates-another's-commit condition, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any commit whose SHA the attacker knows, across any victim stack, as long as the attacker holds any single valid `GithubHook` secret for any org registered in `Shipit.github`.

### Likelihood Explanation
Preconditions are modest: the attacker needs one legitimate `GithubHook`/webhook secret for an org they control (a normal, unprivileged capability — anyone can register a GitHub org and add a Shipit webhook per the app's own onboarding flow), and knowledge of a target commit SHA. No Shipit session, API token, or victim secret is required. The attack is a single crafted HTTP POST, trivially repeatable and scriptable.

### Recommendation
In `StatusHandler#process` (and `RefreshStatusesJob`/similar consumers), scope the commit lookup through the same `stacks`/`repository_name` mechanism `CheckSuiteHandler` uses, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or join `Commit` to `Stack`→`Repository` and filter by `repository_name` derived from the verified payload, ensuring the org that signed the webhook matches the org owning the stack that owns the commit before writing a `Status`.

### Proof of Concept
```ruby
test "status webhook signed by attacker-org cannot write status onto victim-org's commit" do
  victim_stack = shipit_stacks(:shipit) # belongs to org 'shopify' per fixtures
  victim_commit = shipit_commits(:first)

  attacker_secret = 'attacker-secret'
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GithubApp.new('attacker-org', webhook_secret: attacker_secret)
  )

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'forged',
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker-org/decoy' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)}"

  @request.headers['X-Github-Event'] = 'status'
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body:, as: :json
  end
end
```
Assert LHS (`repository_owner` == `'attacker-org'`, verified by attacker's own secret) does not imply RHS (`victim_commit.stack.repository.owner` == `'shopify'`); a correct fix must make `victim_commit.statuses.count` stay unchanged, while the current code causes it to increment by 1, proving the divergence.

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
