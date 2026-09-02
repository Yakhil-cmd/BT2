### Title
Scoped `ApiClient` tokens can read any stack's build status via `CCMenuController`, bypassing their `stack_id` scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` accessor to load the stack directly by URL parameter instead of through the stack-scoped relation used everywhere else in the API. This breaks the binding between the stack(s) an `ApiClient` token is authorized for (`ApiClient#stack_id`) and the stack whose state the request actually touches.

### Finding Description
`Shipit::Api::BaseController` scopes stack access through `stacks`, which restricts results to the token's `stack_id` when the `ApiClient` is stack-scoped: [1](#0-0) 

Every other API controller (e.g. `TasksController`) resolves the target stack through this scoped relation: [2](#0-1) 

`CCMenuController`, however, defines its own `stack` method that loads the stack unscoped: [3](#0-2) 

Authorization is only checked generically via `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`. That method only checks whether the string `"read:stack"` is present in the token's `permissions` array - it never checks the token's `stack_id` against the requested stack: [4](#0-3) 

The mismatch: `stacks` in `BaseController` establishes the equality "the set of stacks a token authorizes == `Stack.where(id: current_api_client.stack_id)`" for every other endpoint, but `CCMenuController#stack` breaks this equality to "any `Stack.from_param!(params[:stack_id])`". A token scoped to stack A (holding only `read:stack` for A) can therefore request `/stacks/:any_stack/ccmenu.xml` for stack B and successfully read B's CI/build state, even though the token was never authorized for B.

This is confirmed by the existing test suite, which explicitly validates that a stack-scoped client is restricted to its one stack on the standard `StacksController#index` endpoint: [5](#0-4) 
No equivalent restriction exists (or is tested) for `CCMenuController`.

### Impact Explanation
This is an unauthenticated-relative-to-scope read of stack state: a token explicitly restricted to a single stack (e.g. issued to a third-party CI dashboard integration for one application) can enumerate `lastBuildStatus`, `lastBuildLabel`, `webUrl`, activity, and lock status for every stack in the Shipit instance, including stacks belonging to unrelated repositories/teams. This matches the in-scope High-severity category "unauthenticated read of stack state, task streams or deploy output," since the disclosure occurs entirely outside the boundary the token issuer intended (`stack_id` scoping).

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token with the `read:stack` permission (the common case for CI/status-badge integrations) can exploit this with a single unauthenticated (from the target stack's perspective) GET request, simply by changing `stack_id` and/or `token` query parameter. No write access, no signature forgery, and no privilege beyond a standard scoped token is required.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation (as used elsewhere), e.g. `stacks.from_param!(params[:stack_id])`, so that the stack a token can query is always constrained to the stacks it was actually authorized for.

### Proof of Concept
1. As an authorized Shipit user, create an `ApiClient` scoped to `stack_id = A` with only the `read:stack` permission (e.g. fixture `here_come_the_walrus`).
2. Using that client's `authentication_token`, issue:
   `GET /api/stacks/:stack_B_id/ccmenu.xml?token=<token>`
   where `stack_B` is any other stack the token was never scoped to.
3. Observe the response returns `stack_B`'s CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc.) with HTTP 200, despite the token only being authorized for `stack_A`, because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!(...)` used by `BaseController`.

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L41-43)
```ruby
      def task
        stack.tasks.find(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```
