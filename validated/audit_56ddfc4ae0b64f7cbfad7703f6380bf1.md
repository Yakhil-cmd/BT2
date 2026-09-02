### Title
Stack-scoped API tokens can read CCMenu build status of any stack, not just the stack they authorize - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper used by every other API controller and resolves the target stack directly from `Stack.from_param!`, bypassing the `ApiClient#stack_id` scoping enforced by `Shipit::Api::BaseController#stacks`/`#stack`. This breaks the binding "the stack a token authorizes == the stack it touches": an `ApiClient` created with `stack_id` set to stack A (and `read:stack` permission) can be used to fetch CCMenu status for any other stack B by simply changing the `stack_id` request parameter.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting stack resolution: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the API client is scoped to a single stack, and `stack` resolves `params[:stack_id]` against that restricted relation. This is the mechanism that turns the `read:stack`/`write:stack`/`deploy:stack` permission strings (which are *not* stack-specific) into an actual per-stack authorization boundary — `ApiClient#check_permissions!` only checks the operation:scope pair, not which stack: [2](#0-1) 

`CCMenuController`, however, defines its own private `stack` method that ignores the scoped `stacks` relation entirely and resolves the parameter against the full `Stack` model: [3](#0-2) 

Because `require_permission :read, :stack` only asserts that the token carries the generic `read:stack` permission string, and the controller's own `stack` override never consults `current_api_client.stack_id`, a token that was created scoped to one specific stack (`ApiClient.stack_id` set) can be pointed at an arbitrary `stack_id` param and will successfully load and render that other stack's `show` action — i.e., the binding "stack authorized by the token" vs "stack actually touched by the token" is broken.

Every other API resource controller (`DeploysController`, `StacksController`, `TasksController`, etc.) relies on the inherited `BaseController#stack`/`#stacks`, which correctly enforces this binding; `CCMenuController` is the outlier that reimplements stack resolution without the scope check.

### Impact Explanation
This is an unauthenticated-relative-to-that-stack read of stack state: a legitimately issued but narrowly-scoped API token (e.g. issued to a CI system or third-party integration for a single project/stack) can be used to read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`, lock status) for every stack managed by the Shipit instance, not just the one it was authorized for. This matches the High-severity category "unauthenticated read of stack state, task streams or deploy output" via a token/scope escalation, since the attacker only needs a token scoped to *any* stack with `read:stack` permission to enumerate/observe all other stacks' deploy state.

### Likelihood Explanation
Likelihood is Medium-High: exploitation requires only possession of a valid, stack-scoped `ApiClient` token with the default `read:stack` permission (a common, low-privilege token type meant to be handed to third-party CI/monitoring tools) and knowledge/guessing of another stack's `stack_id`/param (stack slugs are often derivable from repo/environment naming and are not secret). No signature bypass, no elevated permission, and no session is required — just calling the existing `show` endpoint with a different `stack_id`.

### Recommendation
Remove the private `stack` override in `CCMenuController` and use the inherited, scope-respecting `stack`/`stacks` methods from `BaseController` (i.e., resolve via `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`), so the `ApiClient#stack_id` restriction is honored the same way it is in every other API controller.

### Proof of Concept
1. Create an `ApiClient` scoped to stack A: `ApiClient.create!(stack: stack_a, permissions: ['read:stack'], creator: some_user)`, obtain its `authentication_token`.
2. Using that token (Basic Auth or `?token=`), request `GET /api/{stack_b_owner}/{stack_b_name}/{stack_b_env}/ccmenu.xml` (or the equivalent `stack_id` route param for stack B, which the token was never scoped to).
3. Observe the request succeeds with `200 OK` and returns stack B's `lastBuildStatus`/`lastBuildLabel`/`activity`, even though the token's `ApiClient.stack_id` only references stack A — confirming the `stacks` scoping in `BaseController` is bypassed by `CCMenuController#stack`.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
