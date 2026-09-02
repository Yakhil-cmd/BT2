### Title
Stack-scoped `ApiClient` tokens bypass their stack authorization in `CCMenuController#show` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`ApiClient` records can be scoped to a single `Stack` via `stack_id` [1](#0-0) , and `Shipit::Api::BaseController` enforces that scoping by restricting the visible stack set to `Stack.where(id: current_api_client.stack_id)` before resolving `params[:stack_id]` [2](#0-1) . `Shipit::Api::CCMenuController` overrides this `stack` accessor and resolves the stack directly from `Stack.from_param!(params[:stack_id])`, completely dropping the `current_api_client` scoping check [3](#0-2) .

### Finding Description
The binding that should hold is: `current_api_client.stack_id == stack.id` whenever `current_api_client.stack_id?` is true. `BaseController#stack` enforces this via `stacks.from_param!` where `stacks` is pre-filtered by the client's `stack_id` [2](#0-1) . `CCMenuController` is authenticated through the same `ApiClient.authenticate` mechanism (either via HTTP Basic or a `token` query-string parameter) [4](#0-3) , and only checks the coarse-grained `read:stack` permission with `require_permission :read, :stack` [5](#0-4) . That check (`ApiClient#check_permissions!`) only inspects the `permissions` array, never the `stack_id` [6](#0-5) . Because `CCMenuController#stack` calls `Stack.from_param!` unscoped, any valid, unrevoked `ApiClient` token bound to a specific stack (e.g. a “CCMenu Client” token minted through `CCMenuUrlController` [7](#0-6) , or any admin-created client with `stack_id` set) can be replayed against `GET /api/1/stacks/:stack_id/ccmenu.xml` for an arbitrary `stack_id` belonging to a completely different repository/environment, returning that other stack's latest deploy/rollback status, lock state, and build result.

### Impact Explanation
This satisfies the "High" impact bucket: unauthenticated (relative to the target stack) read of stack state/build output. A token that was only supposed to authorize CI-status polling for one stack can be used to read the deploy status of any stack in the installation, an authorization-scope escalation across stack boundaries — the exact "stack a token authorises versus a stack it touches" binding break called out in scope.

### Likelihood Explanation
Likelihood is high: the attacker needs only a legitimately-issued, stack-scoped `ApiClient` token with `read:stack` permission (a routine, low-privilege credential meant to be embedded in CI dashboards/CCMenu clients) and to change the `stack_id` route parameter — no additional secrets, session, or elevated GitHub permissions are required.

### Recommendation
Make `CCMenuController` reuse the scoped `stack` resolution from `BaseController` (i.e. remove the private `stack` override and rely on `stacks.from_param!`), so the `current_api_client.stack_id` restriction is enforced consistently across all API endpoints, including CCMenu.

### Proof of Concept
1. Create/obtain a stack-scoped `ApiClient` with `permissions: ['read:stack']` and `stack_id` pointing at Stack A (e.g., via `CCMenuUrlController#fetch` for Stack A, or any client whose `stack_id` is set to Stack A's id).
2. Note its `authentication_token`.
3. Issue `GET /api/1/stacks/:stack_id/ccmenu.xml?token=<token>` where `:stack_id` is Stack B's `to_param` (a different, unrelated stack the client was never authorized for).
4. `CCMenuController#authenticate_api_client` accepts the token [4](#0-3) ; `require_permission :read, :stack` passes because the client has `read:stack` regardless of which stack [6](#0-5) ; `stack` resolves Stack B directly via `Stack.from_param!` [8](#0-7) , and the response discloses Stack B's latest deploy/rollback status and lock state.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
