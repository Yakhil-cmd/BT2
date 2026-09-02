### Title
CCMenu API endpoint bypasses stack-scoped ApiClient authorization, allowing cross-stack reads - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` implements a token-scoping mechanism: an `ApiClient` can be limited to a single `Stack` via its `stack_id` column, and all stack lookups are supposed to go through the `stacks` scope that enforces this restriction. `Shipit::Api::CCMenuController` overrides the `stack` accessor to bypass this scope entirely, breaking the binding between "the stack a token is authorized for" and "the stack the request actually touches."

### Finding Description
`BaseController#stacks` is the authorization boundary for stack-scoped tokens: [1](#0-0) 

`ApiClient` has an optional `belongs_to :stack`, and `check_permissions!` only validates the permission string (e.g. `read:stack`), never which specific stack is being accessed: [2](#0-1) [3](#0-2) 

The only place that actually enforces "this token may only touch its assigned stack" is `stacks.from_param!` in `BaseController`. `StacksController` and `HooksController` correctly go through this scoped `stacks`/`stack` helper: [4](#0-3) 

`CCMenuController`, however, redefines `stack` to resolve directly against the global `Stack` table, completely sidestepping the `current_api_client.stack_id` check: [5](#0-4) 

As a result, an `ApiClient` with `read:stack` permission but restricted to a single `stack_id` can query `/api/stacks/:stack_id/ccmenu.xml` for **any** stack, not just the one it is bound to.

### Impact Explanation
This breaks the equality that should hold for any request: `current_api_client.stack_id == stack.id` (when the client is scoped). Before the request, the token is only authorized to read state for Stack A; after the request via `CCMenuController#show`, it successfully reads build status, last build label/time, and activity for Stack B. This is an unauthorized read of stack/deploy state across a token's authorized boundary, matching the "stack a token authorizes vs. a stack it touches" binding called out as in-scope, and falls under the High-impact bucket of "unauthorized read of stack state / deploy output."

### Likelihood Explanation
Any environment where an operator issues a stack-restricted `ApiClient` (e.g., handing a CI dashboard integration limited, single-stack, read-only access) is affected. The holder of that legitimately-scoped, low-privilege token can trivially escalate to read every other stack's deploy status by simply changing `stack_id` in the URL — no additional exploitation complexity is required.

### Recommendation
Have `CCMenuController#stack` reuse the inherited, scope-aware lookup instead of querying `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores enforcement of `current_api_client.stack_id` scoping consistent with `StacksController` and `HooksController`.

### Proof of Concept
1. Admin creates a stack-scoped API client: `ApiClient.create!(creator: admin, name: "Partner CI", permissions: ["read:stack"], stack: stack_a)`.
2. Using `stack_a`'s token, the partner (unprivileged with respect to other stacks) requests:
   `GET /api/stacks/<stack_b_id>/ccmenu.xml?token=<stack_a_scoped_token>`
3. `CCMenuController#authenticate_api_client` succeeds (token is valid, permission `read:stack` present).
4. `CCMenuController#stack` resolves `stack_b` directly via `Stack.from_param!(params[:stack_id])`, ignoring that the token is bound to `stack_a`.
5. Response renders `stack_b`'s deploy/rollback status (name, lastBuildStatus, lastBuildLabel, lastBuildTime), which the token was never authorized to see — confirmed by the boundary check present in `BaseController#stacks` at [6](#0-5)  being absent from `CCMenuController`.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
