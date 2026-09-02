Confirmed: `Shipit::Api::StacksController#stack` correctly uses the scoped `stacks.from_param!(params[:id])` [1](#0-0) , and `BaseController#stacks`/`#stack` enforce that a stack-scoped `ApiClient` can only resolve stacks matching its own `stack_id` [2](#0-1) . `CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `stacks` scoping helper [3](#0-2) , while still relying on `require_permission :read, :stack`, which only checks the permission string via `ApiClient#check_permissions!` and never checks `stack_id` [4](#0-3) .

### Title
Stack-scoped ApiClient token authorizes CCMenu read access to any stack, not just the stack it is bound to - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` supports being scoped to a single stack via `stack_id`, which is the mechanism the engine uses to hand out narrowly-authorized read tokens (e.g., the CCMenu client created per-stack in `CCMenuUrlController`). Every other API controller resolves the target stack through the scoped `stacks` helper, but `Api::CCMenuController#stack` bypasses that helper entirely and resolves the stack straight from `params[:stack_id]` against the full `Stack` table.

### Finding Description
The binding that should hold is: `stack acted on by a request == stack authorized by the token's stack_id (when set)`.

- `BaseController#stacks` implements this binding: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [5](#0-4) , and the default `#stack` method looks up `stacks.from_param!(params[:stack_id])`, i.e., only within that scope [6](#0-5) .
- `Api::StacksController` (and other resource controllers that inherit the default `#stack`) preserve this by calling `stacks.from_param!(...)` [1](#0-0) .
- `Api::CCMenuController` redefines `#stack` to `Stack.from_param!(params[:stack_id])`, dropping the `stacks` scoping filter entirely [3](#0-2) . The only authorization check left is `require_permission :read, :stack`, which merely verifies the client's `permissions` array contains `'read:stack'` — it never compares `current_api_client.stack_id` to the requested `stack_id` [4](#0-3) .

Consequently, any `ApiClient` holding `read:stack` permission — including one deliberately scoped to a single stack via `stack_id` — can call `GET /api/stacks/:stack_id/ccmenu.xml` for *any* stack in the Shipit instance, not just the one it is authorized for. This breaks the "stack a token authorizes vs. stack it touches" binding called out as an in-scope analog class.

### Impact Explanation
This yields unauthorized read access to stack state/deploy status for stacks the token was never granted access to, matching the "High - unauthenticated/escalated read of stack state, task streams or deploy output" impact category. The CCMenu XML response exposes `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, `activity`, and lock state for the target stack, none of which the caller was authorized to see under the stack-scoped token model.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` token (a normal, intentionally low-privilege credential type in this engine, e.g., the auto-provisioned "CCMenu Client" per stack) can trivially exploit this by supplying a different `stack_id` in the URL/path — no special conditions, timing, or race required, and it works with either Basic-Auth or the `?token=` query-string authentication path since both funnel into the same overridden `#stack` method.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped helper, e.g. `stacks.from_param!(params[:stack_id])`, mirroring `BaseController#stack`/`Api::StacksController#stack`, so that stack-scoped `ApiClient` tokens cannot read data for stacks outside their `stack_id`.

### Proof of Concept
1. As an admin, create (or let the app auto-create via `CCMenuUrlController#fetch`) a stack-scoped `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A's id; obtain its `authentication_token`.
2. Using that token, send `GET /api/stacks/<Stack-B-slug>/ccmenu.xml` with `Authorization: Basic <base64(token)>` (or `?token=<token>`), where Stack B is a different, unrelated stack.
3. Observe a `200 OK` with Stack B's build/deploy status XML, even though the token's `stack_id` only authorizes Stack A — because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`, so the `stack_id` restriction is never enforced.

### Citations

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
