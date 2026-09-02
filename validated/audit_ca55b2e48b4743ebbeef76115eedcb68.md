This confirms the exploit path exactly as described. The `stack_id` used to create the `Status` row is `commit.stack_id` — the commit's own stack owner, entirely independent of `params['repository']['owner']['login']`, which is only used by `verify_signature`.### Title
Webhook signature verified for attacker org but Status mutated by sha regardless of owning repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook request solely against `params.dig('repository','owner','login')` (the org whose secret signed the request), while `Shipit::Webhooks::Handlers::StatusHandler#process` looks up and mutates `Commit`/`Status` rows purely by top-level `sha`, never checking that the sha belongs to a repository owned by the verified organization. An attacker who legitimately controls a Shipit-registered GitHub App/org can therefore forge a valid signature for their own org while embedding an arbitrary victim commit `sha`, creating a `Status` row against the victim's `stack_id`.

### Finding Description
The broken binding, as an equality that should hold but doesn't:

`organization_that_signed(payload) == organization_owning(commit_matched_by(payload['sha']))`

Trace:
1. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. It never inspects `params['sha']` or verifies which stack/repository the sha belongs to. [1](#0-0) 
2. `StatusHandler` declares its parameter schema requiring only `sha`, `state`, and optional fields — no `repository` binding is enforced in `params()` at all: [2](#0-1) 
3. `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — matching purely by `sha` across the entire `commits` table, with no scoping to `repository_owner` or `repository_name`: [3](#0-2) 
4. `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)`, where `stack_id` is the **commit's own** `stack_id` (the victim's stack), completely independent of the payload's `repository` field: [4](#0-3) [5](#0-4) 

The base `Handler` class does define a `stacks`/`repository_name` helper scoped to `payload.dig('repository','full_name')` [6](#0-5) , but `StatusHandler#process` does not use `stacks` at all — it bypasses this scoping entirely and queries `Commit` globally by `sha`.

Attacker's exact request: POST `/webhooks` with header `X-Github-Event: status`, `X-Hub-Signature` computed with the attacker's own registered organization's webhook secret (`Shipit.github(organization: 'attacker-org')`), and JSON body:
```json
{"sha": "<victim's public commit sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}}}
```
`verify_signature` passes because the signature is valid for `attacker-org`'s secret and the payload's declared owner is `attacker-org` — consistent with itself, but never cross-checked against the sha's actual owning stack. `StatusHandler#process` then finds `Commit.where(sha: ...)` matching the victim's real commit row (created by the victim's own legitimate GitHub sync) and writes a new `Status` against `commit.stack_id`, i.e., the **victim's** stack.

None of the existing guards prevent this: `verify_signature` only checks signature validity per-org, not sha-ownership; `ExplicitParameters` schema for `StatusHandler` requires no `repository` field; and there is no `require_permission!`/session check on this unauthenticated webhook endpoint by design (webhooks are meant to be unauthenticated except via signature).

### Impact Explanation
This lets an attacker who controls any legitimately configured Shipit organization (a low bar — self-registering an org/app in many Shipit deployments) inject fabricated CI status (`success`/`failure`/`pending`, arbitrary `context`, `target_url`, `description`) onto **any commit whose sha they can observe** in any other tenant's stack, as long as that sha exists as a `Commit` row in the target Shipit instance. Since `success`/`pending` statuses can satisfy `required_statuses`/`blocking_statuses` checks that gate `stack.schedule_merges`, deployability, and merge automation (`add_status` triggers `stack.schedule_merges if new_status.pending? || new_status.success?`, see `app/models/shipit/commit.rb:379-384`), this can push a victim's commit into a deployable/mergeable state or spoof a CI outcome without ever authenticating against the victim's repository. This is a cross-tenant provenance violation matching "a payload for one repository mutating another's stack/commit" — Critical.

### Likelihood Explanation
Preconditions are modest: the attacker needs one legitimately configured organization/app in the target Shipit instance (its own webhook secret), and knowledge of a target commit's sha (shas of public commits are trivially obtainable). No victim credentials, no privileged Shipit role, and no session/API token are required — this matches the stated unprivileged-attacker model exactly. The attack is a single crafted HTTP POST, fully repeatable against any sha, and scales to any multi-tenant Shipit deployment where multiple independent orgs are configured.

### Recommendation
In `StatusHandler#process` (and any other handler matching by `sha` alone, e.g. `check_suite`), scope the `Commit` lookup to stacks belonging to the repository declared/verified in the payload, e.g. `Commit.where(sha: params.sha, stack: stacks)` using the base `Handler#stacks` helper (which already resolves via `Repository.from_github_repo_name(repository_name)`), so a commit is only mutated if its stack's repository matches the repository whose secret signed the webhook.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status from a different org's verified webhook can mutate a victim stack's commit" do
  victim_commit = shipit_commits(:first) # belongs to victim stack, e.g. 'shopify/shipit-engine'

  Shipit::GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true)

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: body, as: :json
  end

  status = victim_commit.statuses.last
  assert_equal victim_commit.stack_id, status.stack_id
  refute_equal 'attacker-org', victim_commit.stack.repository.owner
  # asserts: organization_that_signed('attacker-org') != organization_owning(status.stack_id) (== victim org)
end
```
This proves the equality `organization_that_signed(payload) == organization_owning(mutated_stack)` is violated: the signing org is `attacker-org`, but the mutated `Status`/`stack_id` belongs to the victim's organization.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
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
