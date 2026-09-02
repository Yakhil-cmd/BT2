### Title
Stack-scoped API token authorization bypass in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor used by every other API controller, replacing the tenant-scoped lookup with an unscoped one. This lets any holder of a stack-restricted `ApiClient` token read the build/deploy status of stacks outside the scope the token was authorized for.

### Finding Description
Every other API controller resolves the target stack through `Shipit::Api::BaseController#stack`, which is deliberately scoped to the stacks the authenticated `ApiClient` is allowed to see: [1](#0-0) 

`stacks` restricts the result set to `Stack.where(id: current_api_client.stack_id)` whenever the client carries a `stack_id` (i.e. it was issued for one specific stack), which is exactly the mechanism the test suite documents ("an api client scoped to a stack will only see that one stack") in `test/controllers/api/stacks_controller_test.rb`.

`CCMenuController`, however, defines its own `stack` method that completely bypasses this scoping and resolves the stack straight from the unrestricted `Stack` model: [2](#0-1) 

The only authorization gate left on this action is `require_permission :read, :stack`, which only checks that the string `"read:stack"` is present in `ApiClient#permissions` — it never checks *which* stack the permission applies to: [3](#0-2) 

So the binding that should hold — `api_client.stack_id == stack.id` whenever `api_client.stack_id?` is true — is silently dropped for this one endpoint, while it is enforced everywhere else in the API (`StacksController`, `TasksController`, `DeploysController`, etc., which all rely on `BaseController#stack`/`#stacks`).

This is the same bug class as the report: two different code paths disagree on what data governs an authorization decision — one path (`BaseController#stack`) folds in the caller's scope, the other (`CCMenuController#stack`) silently drops it, exactly like the enforcer that appends `msg.sender` in one call path but not the other.

### Impact Explanation
An `ApiClient` deliberately restricted to a single stack (e.g., issued to a CI job or teammate for stack A) can pass an arbitrary `stack_id` to `GET /api/*/ccmenu` and read the last deploy/rollback status (`lastBuildStatus`, `lastBuildLabel`, lock state, timestamps) of any other stack in the installation, including stacks it was never granted access to. This is an unauthorized read of stack state that escapes the authorization boundary the token was explicitly issued under, matching the High-impact category "escalation into ... unauthenticated read of stack state."

### Likelihood Explanation
Any legitimately-issued, stack-scoped `ApiClient` token with the default `read:stack` permission (the permission needed for the CCMenu integration itself) is sufficient; no privileged or admin credential is required, and the request is a single unauthenticated-w.r.t.-target-stack GET to a documented, publicly reachable endpoint (`ccmenu_url_controller` even hands out tokens for this purpose). The override is a one-line divergence from the pattern used everywhere else, making it easy to miss in review.

### Recommendation
Remove the `stack` override in `CCMenuController` and rely on `BaseController#stack`/`#stacks` so stack-scoped tokens are enforced consistently. If an override is required for query-string authentication, it should still resolve the stack through the scoped `stacks` relation rather than `Stack.from_param!`.

### Proof of Concept
1. Admin issues an `ApiClient` scoped to `stack: stack_a` with `permissions: ["read:stack"]`.
2. Attacker holding that token calls `GET /api/stacks/stack_b/ccmenu.xml?token=<token>` (or via Basic Auth).
3. `authenticate_api_client` succeeds because the token is valid; `require_permission :read, :stack` succeeds because the token has `"read:stack"` in its permission list.
4. `stack` resolves via `Stack.from_param!(params[:stack_id])` — `stack_b` — ignoring that the token's `stack_id` is `stack_a`.
5. The response discloses `stack_b`'s latest deploy/rollback status, contradicting the intended one-stack scope of the token.

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
