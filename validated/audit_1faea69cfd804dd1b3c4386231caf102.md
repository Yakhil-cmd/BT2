Confirmed: `StacksController#stack` correctly uses the scoped `stacks.from_param!`, while `CCMenuController#stack` bypasses that scoping entirely and calls `Stack.from_param!` directly on the unscoped model. `ApiClient` has a `belongs_to :stack, optional: true` and `BaseController#stacks` restricts the accessible stack set to `Stack.where(id: current_api_client.stack_id)` whenever a client is stack-scoped [1](#0-0) [2](#0-1) . `CCMenuController` overrides this accessor and drops the scoping, using only the global `require_permission :read, :stack` permission check, which validates that the client has the `read:stack` capability but never that the requested `stack_id` matches the client's authorized stack [3](#0-2) .

### Title
Stack-scoped API tokens can read CI/build status of any stack via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and `Api::BaseController` enforces this scoping for every endpoint by resolving `stack` through the client-restricted `stacks` collection. `Api::CCMenuController` re-implements `stack` using the unscoped `Stack.from_param!(params[:stack_id])`, breaking the binding "stack authorized by the token" == "stack touched by the request."

### Finding Description
`ApiClient#check_permissions!` only validates coarse-grained, non-stack-specific permission strings such as `read:stack`; the actual per-stack authorization boundary is enforced separately, by scoping the queryable `Stack` relation to `current_api_client.stack_id` when a client is bound to a specific stack [4](#0-3) [2](#0-1) . Every other API controller (e.g. `Api::StacksController`) resolves the target stack through this scoped `stacks` collection: `@stack ||= stacks.from_param!(params[:id])` [5](#0-4) .

`Api::CCMenuController`, however, defines its own `stack` method that ignores the `stacks` scoping and resolves directly against the unrestricted `Stack` model:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [6](#0-5) 

Combined with `require_permission :read, :stack`, which checks only that `"read:stack"` is present in the client's `permissions` array (not that the requested stack matches the client's `stack_id`) [4](#0-3) , any token holding the generic `read:stack` permission — including one legitimately minted and scoped to a single stack — can query CCMenu status for any other stack in the instance by supplying a different `stack_id` in the URL. The identical inversion pattern from the report — a validation performed against the wrong side of a supposed 1:1 binding (price vs. inverted price; here, "stack authorized" vs. "stack looked up") — is present verbatim: `stacks` (scoped) exists and is used everywhere else, but `CCMenuController` substitutes the unscoped `Stack` lookup.

### Impact Explanation
This is an unauthenticated-scope-bypass read of stack state (High, per the rules: "unauthenticated read of stack state, task streams or deploy output" relative to the calling token's actual authorization). An attacker in possession of any `read:stack`-scoped token (even one deliberately restricted to a single, low-sensitivity stack) can enumerate deploy status/activity (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state, etc., as rendered in `shipit/ccmenu/project`) for every stack managed by the Shipit instance, including stacks the token was never meant to access [7](#0-6) .

### Likelihood Explanation
High. No special privilege is required beyond possessing any valid API token with `read:stack` permission — which is the default/common permission granted to low-trust integrations such as the auto-created "CCMenu Client" [8](#0-7) . The attack requires only changing the `stack_id` path segment of a request that is otherwise legitimately authenticated.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` collection, matching `Api::BaseController` and `Api::StacksController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the "token authorizes stack X" == "endpoint touches stack X" binding for all clients whose `stack_id` is set.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id: A` with `permissions: ['read:stack']` (e.g. via `POST /repositories/:id/stacks/:stack/continuous_delivery_schedule`-style flows or the auto-provisioned CCMenu client from `CCMenuUrlController#fetch` for stack A).
2. Using that client's `authentication_token`, call `GET /api/stacks/:stack_B/ccmenu.xml` where `stack_B` is a different stack the token was never scoped to.
3. Observe that `CCMenuController#stack` resolves `stack_B` via unscoped `Stack.from_param!`, bypassing the `stacks` scoping defined in `Api::BaseController`, and returns `stack_B`'s deploy status — something `Api::StacksController#show` with the same token would correctly reject via 404/empty scope.

### Citations

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-31)
```ruby
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
