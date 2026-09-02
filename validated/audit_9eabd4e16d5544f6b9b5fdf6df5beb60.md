### Title
CCMenuController resolves the `stack_id` param against all stacks instead of the token's authorized scope, breaking the ApiClient stack-scope binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
This is a structural analog of the reported "field updated but never persisted / verified" bug class: a security-relevant binding (the stack an `ApiClient` token is scoped to) is established at authentication time but never actually enforced at the point the resource is fetched. `Shipit::Api::CCMenuController#stack` bypasses the scoped lookup used everywhere else in the API and resolves `params[:stack_id]` against the entire `Stack` table.

### Finding Description
`Shipit::Api::BaseController` defines the canonical binding between an `ApiClient`'s authorized scope and the stack it may act on: [1](#0-0) 

`stacks` is scoped to `current_api_client.stack_id` when the client is stack-scoped, and `stack` is derived from that scoped relation via `stacks.from_param!(params[:stack_id])`. This is the equality the whole API is supposed to preserve: `stack the token authorizes == stack the token touches`.

`CCMenuController` overrides this and calls `Stack.from_param!(params[:stack_id])` directly, on the unscoped `Stack` model, instead of using the scoped `stacks` helper: [2](#0-1) 

The controller only guards access with `require_permission :read, :stack`, which checks the *permission list* (`current_api_client.check_permissions!`) on `ApiClient`: [3](#0-2) 

but `check_permissions!` only validates that `"read:stack"` is present in `permissions` — it never checks `current_api_client.stack_id`. Because `stack` in `CCMenuController` is resolved from the global `Stack` table rather than from `stacks` (scoped by `current_api_client.stack_id`), a token that was created scoped to one specific stack (e.g. via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator:, stack:)`, as done in `CCMenuUrlController`) can be replayed against **any other stack ID** by simply changing `params[:stack_id]` in the request to the `ccmenu` endpoint. [4](#0-3) 

This mirrors the audit's root cause exactly: a binding (`order.prevOrderId` set in memory but never persisted to the storage struct actually read later) that is computed once but not carried through to the code path that acts on it. Here, the "stack a token authorizes" is computed and enforced in `BaseController#stack`, but `CCMenuController` re-implements `#stack` without carrying that scoping through, so the enforced value and the acted-upon value diverge.

### Impact Explanation
An `ApiClient` token intentionally scoped to a single stack (the common case — see `CCMenuUrlController#client`, which creates `read:stack`-scoped tokens tied to one stack, and hands the token+URL to external CI dashboards) can be used to read deploy/rollback status (`stack.deploys_and_rollbacks.last`) for **every stack in the Shipit instance**, not just the one it was issued for. This is an unauthorized read of stack state across repositories/stacks using a token that was deliberately restricted to one stack — a cross-scope information disclosure enabled purely by bypassing the scope-binding check, matching the "unauthenticated/unauthorized read of stack state" High-impact category in the rules.

### Likelihood Explanation
High. No special privileges are required beyond possessing one legitimately-scoped CCMenu token (these are routinely embedded in unauthenticated CI-dashboard URLs per `CCMenuUrlController`), and the attack is a single GET request with a different `stack_id` query/path parameter. No signature, session, or write access is needed — it is a straightforward parameter substitution against an endpoint that forgot to reuse the shared scoping helper.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` helper inherited from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped `ApiClient` tokens cannot be used to access stacks outside their `stack_id` binding.

### Proof of Concept
1. Create a stack-scoped `ApiClient` token for `stack_a` with `permissions: ["read:stack"]` (as `CCMenuUrlController#client` does).
2. Call `GET /api/stacks/:stack_a_id/ccmenu.xml?token=<token>` — succeeds as intended.
3. Call `GET /api/stacks/:stack_b_id/ccmenu.xml?token=<token>` (any other stack's id/param, same token) — because `CCMenuController#stack` uses `Stack.from_param!` on the whole table rather than `stacks.from_param!` scoped to `current_api_client.stack_id`, this request also succeeds and returns `stack_b`'s deploy/rollback status, even though the token was only ever authorized for `stack_a`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
