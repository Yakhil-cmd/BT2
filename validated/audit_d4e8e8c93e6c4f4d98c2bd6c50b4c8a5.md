## Title
`Api::CCMenuController` bypasses stack-scoped `ApiClient` authorization, allowing a stack-scoped token to read status of unauthorized stacks - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `Api::BaseController` enforces an equality binding: **stack authorized by token == stack served to caller**, implemented via `stacks`/`stack` which filter by `current_api_client.stack_id`. `Api::CCMenuController` overrides `stack` to bypass that filter entirely, breaking the binding and letting a stack-scoped `ApiClient` token read deploy/task status for any stack in the instance.

### Finding Description
`Api::BaseController` scopes stack lookups to the authenticated `ApiClient`'s authorized stack when the client is stack-scoped: [1](#0-0) 

This is the intended binding: `current_api_client.stack_id` == the only stack the client's `stack` accessor can resolve to.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping and instead resolves directly from the raw request parameter, with no reference to `current_api_client` at all: [2](#0-1) 

The `require_permission :read, :stack` before_action only checks the client's permission list via `ApiClient#check_permissions!`, which is scope-name based (`"read:stack"`), not stack-id based: [3](#0-2) 

So an `ApiClient` created with a `stack_id` (i.e., intentionally restricted to one stack, per `belongs_to :stack, optional: true` and the auto-generated `stack_id?` predicate used elsewhere) and the `read:stack` permission passes the permission check for *any* stack, and then `CCMenuController#stack` resolves whatever `stack_id` param the caller supplied — not the one the token was scoped to.

This is directly analogous to the reported bug class: in the Solidity report, `amount0`/`amount1` were computed against a reserve value that silently diverged from the value actually authorized/used elsewhere (`_update`'s fee-adjusted reserve vs `mint`'s naive balance-reserve diff). Here, the "stack the token authorizes" (`current_api_client.stack_id`) diverges from "the stack actually touched" (`params[:stack_id]` resolved unscoped) in one specific controller that reimplements the accessor instead of reusing the scoped one.

### Impact Explanation
Any holder of a valid, deliberately stack-scoped `ApiClient` token (with only `read:stack` permission on their own stack) can query `GET /api_clients/... /cc.xml?stack_id=<any_other_stack>&token=<their_token>` and receive that other stack's latest deploy/rollback status (id, timestamp, running/passing state) — data belonging to a stack they were never authorized to see. This is an unauthorized read of stack/task/deploy output across a token's intended boundary, matching the "High - unauthenticated/unauthorized read of stack state, task streams or deploy output" impact category via the "stack a token authorises versus a stack it touches" binding break called out in scope.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a documented, supported feature: `ApiClient belongs_to :stack, optional: true`) to less-trusted integrations (e.g., CI dashboards, CCTray consumers). No special privilege beyond possessing one such token is required; the attacker only changes the `stack_id` query parameter, since `CCMenuController#stack` performs no ownership check.

### Recommendation
Make `CCMenuController#stack` reuse the scoped `stacks`/`stack` resolution from `BaseController` (i.e., remove the local override, or restrict `Stack.from_param!` to `stacks` scoped by `current_api_client.stack_id?`), so the CCMenu endpoint honors the same authorization binding as every other API controller.

### Proof of Concept
1. Admin creates an `ApiClient` scoped to `stack_id: A` with permission `read:stack`, and gets `authentication_token`.
2. Attacker (holder of this token) issues:
   `GET /api_clients/<id>/cc.xml?token=<token>&stack_id=<B>` where `B` is a different stack.
3. `authenticate_api_client` succeeds (valid token) via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because the client has `"read:stack"` in its permission list, irrespective of which stack.
5. `stack` resolves `Stack.from_param!(params[:stack_id])` == stack `B`, unscoped by `current_api_client.stack_id`.
6. Response renders stack `B`'s latest deploy/rollback status — data outside the token's authorized stack `A`.

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
