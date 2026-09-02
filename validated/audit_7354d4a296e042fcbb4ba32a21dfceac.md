### Title
Stack-scoped `ApiClient` tokens can read the CCMenu status of any stack, bypassing token stack scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` (one with `stack_id` set) may only see/operate on that single stack, by routing all stack lookups through the `stacks` collection method. `Shipit::Api::CCMenuController` overrides `#stack` to bypass this scoping entirely, resolving `params[:stack_id]` against the full `Stack` table regardless of the authenticated token's `stack_id`.

### Finding Description
`BaseController#stacks` restricts the visible set of stacks to the ones a scoped token is authorized for: [1](#0-0) 

Every other API controller that resolves `stack` from `params[:stack_id]` (e.g. `StacksController`) goes through this scoped `stacks` collection, so a token created with `stack_id` set (see the `here_come_the_walrus` fixture) is confirmed to be limited to a single stack in `test/controllers/api/stacks_controller_test.rb` ("an api client scoped to a stack will only see that one stack").

`CCMenuController`, however, defines its own `#stack` that queries the global `Stack` model directly, never consulting `current_api_client.stack_id`: [2](#0-1) 

`require_permission :read, :stack` (from `BaseController`) only checks that the token has the string permission `read:stack` in `ApiClient#check_permissions!`: [3](#0-2) 

It never checks whether the requested `stack_id` matches the token's `stack_id`. The binding broken is: `stack a token authorises` (`ApiClient#stack_id`) `!= stack it touches` (`params[:stack_id]` resolved unscoped in `CCMenuController#stack`).

### Impact Explanation
An `ApiClient` token deliberately scoped to a single stack (the least-privilege pattern the engine supports, e.g. tokens auto-created per-stack by `CCMenuUrlController`, or manually scoped via `ApiClientsController`) can be used to read the build/deploy state (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock status, etc.) of *any* stack in the Shipit instance by simply changing the `stack_id` route parameter, defeating the purpose of scoping the credential. This is an authorization-boundary bypass on a credential that was explicitly restricted to a single repository/stack, matching the "stack a token authorises vs. stack it touches" binding and constituting unauthorized read of stack state for stacks the token holder should have no visibility into.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token (which by design has a `read:stack` permission and is meant to be handed to lower-trust consumers, e.g. an external CI/status dashboard for one project) can trivially exploit this by requesting `GET /api/stacks/:other_stack_id/ccmenu.xml` with their own token and an arbitrary `stack_id`. No special access or knowledge beyond possession of any valid scoped token is required.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection (same as `BaseController#stack`), e.g. `stacks.from_param!(params[:stack_id])`, instead of querying `Stack` directly, so stack-scoped tokens cannot read state for stacks outside their authorized scope.

### Proof of Concept
1. Create/have an `ApiClient` scoped to stack A: `ApiClient.create!(creator: user, name: 'x', stack: stack_a, permissions: ['read:stack'])`.
2. As that client, request `GET /api/stacks/:stack_b_id/ccmenu.xml?token=<stack_a_token>` where `stack_b` is an unrelated stack.
3. Observe that `CCMenuController#stack` resolves `stack_b` via `Stack.from_param!(params[:stack_id])` (ignoring `current_api_client.stack_id == stack_a.id`), and the response renders `stack_b`'s deploy status — proving the token escaped its authorized stack scope.

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
