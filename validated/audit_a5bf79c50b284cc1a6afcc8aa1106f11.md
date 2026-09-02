### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a single-stack-scoped token to read any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController#stack` re-implements stack lookup instead of reusing `BaseController#stack`, and in doing so drops the scoping to `current_api_client.stack_id`. This lets an `ApiClient` token that was explicitly restricted to a single stack read the CCMenu deploy-status XML of any stack in the Shipit instance, exactly the "token-authorised-stack vs. stack-actually-touched" binding break called out in the analog rules.

### Finding Description
`ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces this scope centrally through the `stacks`/`stack` helper methods:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that relies on the inherited `stack` method (e.g. `TasksController`, `LocksController`, `MergeRequestsController`, `RollbacksController`) is correctly confined to `current_api_client.stack_id` when the token is scoped.

`CCMenuController`, however, overrides `stack` and calls `Stack.from_param!` directly, bypassing the `stacks` scoping relation entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`Stack.from_param!` performs an unscoped lookup across the whole `Stack` table by `owner/name/environment`:
```ruby
def self.from_param!(param)
  repo_owner, repo_name, environment = param.split('/')
  includes(:repository)
    .where(repositories: { owner: repo_owner.downcase, name: repo_name.downcase }, environment:)
    .first!
end
``` [4](#0-3) 

The only authorization gate on this controller is `require_permission :read, :stack`, which checks that the client's `permissions` array contains `read:stack` [5](#0-4) [6](#0-5)  — it never checks that the requested `stack_id` matches the token's bound `stack`. Since `stack_id` is an attacker-supplied path/query parameter, the caller can substitute any other stack's `owner/name/environment` string.

**Binding broken (equality that should hold but doesn't):**
`ApiClient#stack_id` (the stack the token is authorized for) ≠ the `stack` object actually rendered by `CCMenuController#show`. Every other stack-scoped API controller preserves this equality via `stacks.from_param!`; `CCMenuController` silently drops it.

### Impact Explanation
An `ApiClient` deliberately created with a narrow scope (`stack: some_stack`, permission `read:stack`) — the least-privileged kind of API credential Shipit supports — can be used to read the CI/deploy status (name, activity, lastBuildStatus, lastBuildLabel, lastBuildTime, webUrl) of every stack hosted by the Shipit instance, including private/unrelated projects the token was never meant to see. This is an unauthenticated-for-that-resource read of stack state, matching the "High - ... unauthenticated read of stack state, task streams or deploy output" impact bucket, achieved purely by escalating a legitimately-scoped low-privilege credential beyond its intended authorization boundary — no webhook secret, GitHub App key, or elevated account is needed beyond the scoped token itself.

### Likelihood Explanation
High. Any Shipit operator who issues per-project/scoped API tokens (a documented, intended-lower-privilege use case, e.g. for CI dashboards) is exposed. Exploitation requires only a single unauthenticated GET request with a different `stack_id`; no race conditions, timing, or privileged access are needed, and the `token` can even be passed as a query-string parameter per `CCMenuController#authenticate_api_client` [7](#0-6) , making it trivial to script.

### Recommendation
Remove the private `stack` override in `CCMenuController` (or reimplement it using the inherited `stacks` relation) so that it honors `current_api_client.stack_id` the same way every other stack-scoped API controller does:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. As a Shipit admin (or self-service if enabled), create an `ApiClient` scoped to `stack: project_a` with only `read:stack` permission, and note its `authentication_token`.
2. Using that token, issue:
   `GET /api/stacks/other_owner/other_repo/production/cc.xml?token=<token>`
   (any `stack_id` belonging to a different, unrelated stack).
3. Observe HTTP 200 with a valid CCMenu XML payload for `other_owner/other_repo/production`, even though the token is bound to `project_a` — confirmed by `CCMenuController#stack` calling `Stack.from_param!` instead of the scoped `stacks.from_param!` used everywhere else, as shown in `test/controllers/api/ccmenu_controller_test.rb` (which only exercises the token's own scoped stack and never verifies cross-stack rejection) [8](#0-7) .

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-24)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
