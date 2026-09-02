### Title
Cross-tenant `Status` creation via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no scoping to the repository named in the webhook payload, then calls `create_status_from_github!` on every matching row. Because git SHAs (especially initial/empty commits, or any commit content that happens to be identical across forks) are not globally unique to a single repository, one validly-signed webhook from organization O's repository can create `Status` rows on stacks belonging to unrelated organizations that happen to share that SHA.

### Finding Description
The broken binding: the code should enforce `commit.stack.repository.full_name == payload['repository']['full_name']` (equivalently `commit.stack ∈ Handler#stacks`) for every `Commit` row mutated by `process`, but no such check exists.

Code path:
- `Shipit::WebhooksController#create` parses the JSON body and dispatches to handlers matching the event type: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` resolves the GitHub App via `repository_owner` (`params.dig('repository','owner','login')`) and verifies the HMAC signature against that organization's webhook secret [2](#0-1) . This proves the payload was sent by GitHub for a repository under organization O only — it does not, and cannot, constrain which `Commit`/`Stack` rows the handler is allowed to touch.
- `Handler#initialize`/`.call` just parses params via the `ExplicitParameters` schema and calls `process` [3](#0-2) . The base `Handler` class provides a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, intended for handlers to restrict their effect to the repository actually named in the payload [4](#0-3) .
- `StatusHandler#process`, however, never uses `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` directly against the whole `commits` table and iterates every match regardless of which stack/repository/organization owns it: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) .
- `create_status_from_github!` unconditionally writes a `Status` row for the commit's own `stack_id` via `statuses.replicate_from_github!(stack_id, github_status)` [6](#0-5) , and `Status.replicate_from_github!` does a `find_or_create_by!` scoped only by that `stack_id`/state/context [7](#0-6) . Creation of a `Status` also has side effects: it enables CI on the target stack and schedules continuous delivery/merge-request processing for that stack, per `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` [8](#0-7) , [9](#0-8) .

Attacker request: an attacker who owns/controls a GitHub repository under their own organization can create a commit whose SHA matches a `Commit` already recorded in Shipit for other tenants' stacks — trivially achievable for the well-known empty/initial commit SHA, or by cherry-picking/duplicating an existing public commit into their fork — and then trigger (or directly emit, since delivery is a normal `status` webhook event) a `status` webhook naming their own repository. Because the signature check only validates that *some* payload came from GitHub for the attacker's own org, and `StatusHandler#process` doesn't further scope by `repository_name`, the single event causes `Status` rows (and cascading CI/merge effects) to be written on every unrelated stack across every organization that has a `Commit` with the same `sha`.

Existing guards checked and why they don't stop this: `verify_signature` only authenticates *who sent this payload*, not *which stacks it may mutate* [2](#0-1) ; the `ExplicitParameters` schema in `StatusHandler` only validates presence/type of `sha`/`state`/etc, not repository scoping [10](#0-9) ; the `Handler#stacks` scoping helper exists in the base class but is simply not invoked by `StatusHandler#process`.

### Impact Explanation
A single authenticated webhook from one organization mutates `Status` rows belonging to stacks under unrelated organizations that share a commit SHA — this is exactly the "payload for one repository mutating another's stack/commit" critical category. Blast radius is unbounded: every stack across every tenant containing a `Commit` row with the colliding SHA is affected by one request, and this is repeatable at will by the attacker for any SHA they can arrange to collide (trivially the empty initial commit, common in many repositories/forks). Downstream effects include forcing CI-enablement (`enable_ci_on_stack`) and triggering continuous delivery/merge-request processing jobs on victim stacks, which can influence real deploy decisions.

### Likelihood Explanation
Preconditions are modest: the attacker needs their own GitHub repository (unprivileged, self-controlled) with a commit whose SHA collides with a `Commit` row already synced into other tenants' Shipit stacks (e.g., the canonical empty commit SHA, or a duplicated public commit such as a well-known upstream fix). No Shipit credentials, GitHub App secrets, or team membership are required — only the attacker's own valid GitHub webhook delivery for their own repository, which GitHub will sign correctly for that repository's organization. This is straightforward and repeatable.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring the base `Handler#stacks` helper, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
so only commits belonging to stacks under `repository_name` (the repository whose owner's signature was verified) are ever mutated.

### Proof of Concept
Minitest plan (e.g. add to `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create three fixtures: `stack_a` (org A / repo A), `stack_b` (org B / repo B), `stack_c` (org C / repo C), each unrelated tenants.
2. Create three `Commit` rows, one per stack, all sharing the identical `sha` value `"deadbeef" * 5` (or the well-known empty tree/commit sha).
3. Stub `GithubHook#verify_signature` (or the equivalent app-level `verify_webhook_signature`) to return true only for org A, simulating a legitimately signed webhook from org A only.
4. POST a `status` webhook body naming only `stack_a`'s repository in `repository.full_name`, with the shared `sha` and `state: 'success'`.
5. Assert the broken binding directly:
   - Before: `Status.where(stack_id: [stack_b.id, stack_c.id]).count == 0` and `Status.where(stack_id: stack_a.id).count == 0`.
   - After posting: `assert_difference 'Status.count', 3 do ... end`, then assert `Status.exists?(stack_id: stack_b.id)` and `Status.exists?(stack_id: stack_c.id)` are both `true`, even though only `stack_a`'s repository was named in the payload — demonstrating `commit.create_status_from_github!` fired for stacks whose owning organization never authenticated the request.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** app/models/shipit/status.rb (L38-44)
```ruby
    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
