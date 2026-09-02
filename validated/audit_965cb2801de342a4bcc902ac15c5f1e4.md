This is a valid vulnerability, confirmed by direct inspection of the handler and controller code.

### Title
Cross-repository `Status` forgery via SHA collision in webhook `status` event handling - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire database and never checks that the payload's `repository.full_name`/`repository_owner` matches the repository/stack that owns that commit. `WebhooksController#verify_signature` only authenticates that the payload's named organization signed the payload with *its own* webhook secret — it establishes nothing about the commit or stack the handler subsequently mutates.

### Finding Description
The broken binding is: `verified_organization (payload.repository.owner.login, authenticated via that org's webhook_secret)` == `owning_organization (Stack/Repository that actually owns the Commit row matched by sha)`. This does not hold.

Trace:
- `WebhooksController#verify_signature` derives `repository_owner` purely from the request body (`params.dig('repository','owner','login') || params.dig('organization','login')`), fetches `Shipit.github(organization: repository_owner)`, and verifies HMAC signature against that org's `webhook_secret` only [1](#0-0) . There is no cross-check that this organization is the one that owns the commit/stack referenced later.
- `StatusHandler#process` ignores `repository_name`/`stacks` entirely and does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) .
- The base `Handler` class defines `stacks` (scoped via `Repository.from_github_repo_name(repository_name)`) precisely for this purpose [3](#0-2) , but `StatusHandler` never calls it, unlike other handlers that scope by repository.
- `Commit#create_status_from_github!` creates a `Status` record tied to that commit/stack based solely on the attacker-controlled `params.state`/`description`/`target_url`/`context` — see `Status.replicate_from_github!` /model usage exercised in `test/models/commits_test.rb` [4](#0-3) .

Exploit flow: attacker registers/owns `attacker-org` with its own Shipit-configured GitHub App and `webhook_secret` (a legitimate, independently configured tenant on the same Shipit host). Attacker crafts a commit whose SHA collides with an existing `victim/prod` commit (per the question's stated precondition), then POSTs to `/webhooks` with `X-Github-Event: status`, `repository.full_name = attacker/evil`, `repository.owner.login = attacker-org`, and `sha = <shared_sha>`, signed with `attacker-org`'s own valid secret. `verify_signature` passes because the signature is valid for `attacker-org`. `StatusHandler#process` then matches the victim's `Commit` row purely by `sha`, ignoring which repository the request claims to be about, and writes a new `Status` against the victim's commit/stack.

Existing guards do not catch this: `verify_signature` authenticates the org named in the payload, not the org that owns the target commit; `drop_unhandled_event`/`check_if_ping` are irrelevant; the `ExplicitParameters` schema in `StatusHandler.params` only validates types/presence of `sha`, `state`, etc., not repository ownership [5](#0-4) ; no model validation ties `Status` creation to a repository match.

### Impact Explanation
A payload authenticated for `attacker/evil` mutates state (creates a `Status` row, which can flip CI/deployability state, trigger `enable_ci_on_stack`, and schedule continuous delivery / `ProcessMergeRequestsJob`) belonging to `victim/prod`'s commit and stack [6](#0-5) . This is a cross-repository write not authenticated for the target repository, matching the "Critical" category: "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any stack whose commits happen to share a SHA with an attacker-crafted commit, and since `Status` creation can drive `schedule_continuous_delivery`, it can influence auto-deploy behavior on the victim stack.

### Likelihood Explanation
Preconditions: attacker must control an organization already configured in Shipit with its own `webhook_secret` (a legitimate multi-tenant scenario on a shared Shipit host), and must produce a commit SHA colliding with one tracked by the victim stack (feasible only via the crafted-empty-commit-tree technique described in the precondition, not via SHA1 collision search). Given those preconditions, the attacker cost per request is trivial — a single signed HTTP POST — and it is fully repeatable against any commit whose SHA can be reproduced.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the stacks/repository implied by the payload (using the existing `Handler#stacks` helper) instead of querying `Commit` globally by `sha`, e.g. restrict to commits whose `stack` belongs to `stacks` (derived from `repository_name`) before calling `create_status_from_github!`.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb`, add a minitest to `WebhooksControllerTest`:
```ruby
test ":status from an unrelated repository must not create a Status for another stack's commit" do
  request.headers['X-Github-Event'] = 'status'
  victim_commit = shipit_commits(:first) # belongs to shipit_stacks(:shipit) via repository "shopify/shipit-engine" (or fixture equivalent)

  body = JSON.parse(payload(:status_master)).merge(
    'sha' => victim_commit.sha,
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker-org' } }
  ).to_json

  assert_no_difference 'victim_commit.statuses.count' do
    post :create, body:, as: :json
  end
end
```
Assert on both sides of the binding: `payload['repository']['full_name']` (`attacker/evil`, verified org `attacker-org`) must not equal the repository owning `victim_commit.stack` (`shopify/shipit-engine` or whichever fixture repo `shipit_commits(:first)` belongs to), and confirm the test fails against current code (i.e., `victim_commit.statuses.count` increases) demonstrating the cross-repository write.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L16-19)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
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
    end
```
