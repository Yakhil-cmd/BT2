### Title
CCMenu controller lets any `read:stack` API token read the build/deploy status of a stack it was never scoped to - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack with a raw, unscoped lookup (`Stack.from_param!(params[:stack_id])`) instead of going through the tenant-scoping helper `stacks` used by every other API controller. This breaks the binding "the stack a token authorises == the stack it touches": an `ApiClient` that is restricted to a single stack (`current_api_client.stack_id?` true) can nonetheless be used to fetch CCMenu/CCTray build-status XML for *any* stack in the installation simply by changing the `stack_id` route param.

### Finding Description
`BaseController` establishes the authorization invariant for every scoped `ApiClient`: [1](#0-0) 

`stacks` filters the visible `Stack` relation down to `current_api_client.stack_id` when the client is scoped, and `stack` (the default implementation used by e.g. `StacksController`) resolves the requested stack *through that filtered relation*, so `from_param!` raises `ActiveRecord::RecordNotFound`/404 if the client tries to touch a stack outside its authorized scope.

`CCMenuController` overrides both the authentication method and the `stack` accessor, but only re-implements the authentication half correctly. The `stack` method no longer goes through `stacks`: [2](#0-1) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks the string permission list, not stack identity: [3](#0-2) 

So the only enforcement left is "does this token have the `read:stack` permission at all" — the per-stack scope (`current_api_client.stack_id`) that other controllers rely on to bind a token to one stack is silently dropped in this controller. Any `read:stack` scoped token can therefore be replayed against `params[:stack_id]` values it was never issued for.

Before the attacker's request: `ApiClient#stack_id` == Stack A (the only stack the token holder is meant to see).
After the attacker's request: the controller returns build/deploy status for Stack B (or any stack), because `stack` never consults `current_api_client.stack_id`.

This is the direct analog of the report's bug class: a credential (the CCMenu/API token — the "signature") is checked for validity and for a coarse permission ("read:stack"), but a field in the request that should be bound by that credential's issuance context (`stack_id`) is never verified against what the credential was actually authorized for, exactly as arbitrary-signature reuse lets a signature meant for one context be replayed in another.

### Impact Explanation
This grants unauthenticated read of stack build/deploy state across tenant boundaries using a token that was only supposed to grant visibility into one stack (e.g., a CCMenu URL embedded in a third-party CI dashboard, per `CCMenuUrlController`). An attacker holding (or capturing, since these URLs are designed to be embedded unauthenticated in third-party tools) any single scoped read token can enumerate/read `lastBuildStatus`, `lastBuildLabel`, `webUrl`, activity, and lock state for every stack in the Shipit installation, not just the one the token/URL was generated for. This matches the in-scope High-severity bucket "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Likelihood is high for anyone who already holds one legitimate, narrowly-scoped `read:stack` CCMenu token — the exact kind of low-privilege credential these tools are designed to hand out to third-party CI dashboard software over unauthenticated URLs. No additional privileges, session, or write access are required; only changing a single route parameter (`stack_id`) is needed to pivot to arbitrary stacks.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation instead of `Stack.from_param!` directly, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so a client whose `stack_id` is set can never resolve a stack outside that scope, restoring the same invariant enforced in `StacksController`, `TasksController`-style API resources, etc.

### Proof of Concept
1. As an admin, create (or have `CCMenuUrlController#client` auto-create) an `ApiClient` scoped to Stack A with permission `read:stack` and note its `authentication_token`.
2. Send `GET /api/stacks/*stack_id/ccmenu?token=<TOKEN>` with `stack_id` set to Stack B's identifier (a different, unrelated stack in the same Shipit instance).
3. Observe the response returns Stack B's CCTray XML (`name`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc.) even though the token was only meant to authorize reads of Stack A, because `CCMenuController#stack` never checks `current_api_client.stack_id` against the requested `stack_id`.

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
