### Title
CCMenu API endpoint discloses stack status outside the stack scope authorized by the requesting `ApiClient` token - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and every API controller is supposed to enforce that scope by resolving requested stacks through the `stacks` helper in `BaseController`. `Api::CCMenuController` bypasses this helper and resolves the stack directly from the unscoped `Stack` model, breaking the binding between "the stack a token authorizes" and "the stack the endpoint actually touches."

### Finding Description
`Shipit::Api::BaseController` defines the authorization-scoping mechanism for all API endpoints: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the authenticated `ApiClient` is scoped to a stack, and `stack` resolves `params[:stack_id]` only within that restricted relation. `Stack#from_param!` raises when the id/param isn't found in the relation it's called on, so calling it on the unscoped `stacks` relation is what actually enforces the per-token stack restriction — the restriction lives entirely in which relation `from_param!` is invoked on, not in `check_permissions!`.

`Api::CCMenuController` overrides `stack` and calls `from_param!` on the unscoped `Stack` model directly, instead of on `stacks`: [2](#0-1) 

The only authorization check performed is `require_permission :read, :stack`, which is enforced by `ApiClient#check_permissions!`: [3](#0-2) 

This check only verifies that `"read:stack"` is present in the client's `permissions` array — it has no notion of *which* stack, so it does not compensate for the missing scoping. This is analogous to the reported `loan.hash()` bug: a field that matters for authorization (`stack_id` scope / `protocolFee`) is checked by a component (`check_permissions!` / `_baseLoanChecks`) that doesn't actually cover it, so an attacker can substitute an unauthorized value (`params[:stack_id]` pointing to a different stack / an arbitrary `protocolFee`) and the check silently passes.

Concretely: `ApiClient.stack_id?` == true (token authorizes only stack A) vs. the stack actually rendered by `CCMenuController#show` can be any stack B chosen via `params[:stack_id]`, because `Stack.from_param!` has no knowledge of `current_api_client`.

### Impact Explanation
An attacker holding a valid, stack-scoped `ApiClient` token (e.g. one created by `CCMenuUrlController` for a specific stack and leaked via a build-status URL, which is the token's designed usage pattern) can read the merge status, latest build status/label, activity ("Building"/"Sleeping"), and last build time of any stack in the Shipit instance, not just the one the token was issued for. This is an unauthorized read of stack state via a credential intentionally scoped to a narrower resource — matching the "unauthenticated/unauthorized read of stack state" High-impact bucket, since the token's declared authorization boundary (one stack) is bypassed.

### Likelihood Explanation
High likelihood for anyone already possessing any `read:stack`-scoped `ApiClient` token (including the low-privilege CCMenu tokens Shipit itself generates for embedding in third-party CI dashboards, per `CCMenuUrlController`). No additional privilege, session, or GitHub access is required beyond a token that is expected to be narrowly scoped; only `params[:stack_id]` needs to be changed.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation, mirroring `BaseController`:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This ensures the equality `stack authorized by token == stack touched by controller` holds, consistent with every other API controller relying on `BaseController#stack`.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, name: 'x', permissions: ['read:stack'], stack: stack_a)` (this is exactly what `CCMenuUrlController#client` does for any user who visits a stack's CCMenu URL feature).
2. Using that client's `authentication_token` as Basic Auth credentials, issue:
   `GET /api/stacks/:stack_b_id/ccmenu.xml` where `stack_b` is a different, unrelated stack.
3. `authenticate_api_client` succeeds because the token is valid; `require_permission :read, :stack` passes because the token has `read:stack` in its permission list (scope-agnostic check).
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (unscoped), resolves Stack B, and `show` renders Stack B's build status/label/activity in the XML response — despite the token only being authorized for Stack A.

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
