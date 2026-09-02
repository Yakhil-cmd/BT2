### Title
Stack-scoped ApiClient token can read CCMenu status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` restricts every API endpoint to the stack(s) an `ApiClient` is authorized for via the `stacks`/`stack` helper methods, which check `current_api_client.stack_id?` before resolving `params[:stack_id]`. `Shipit::Api::CCMenuController` overrides `#stack` and resolves the target record directly from `Stack.from_param!(params[:stack_id])`, completely bypassing the client's `stack_id` restriction. This breaks the equality "stack a token is authorized for" == "stack a token can touch" for this endpoint.

### Finding Description
`BaseController` defines the authorization-scoping primitives used by every other API controller: [1](#0-0) 

`stacks` returns only the stack the `ApiClient` is bound to when `stack_id` is set, and `stack` resolves `params[:stack_id]` through that restricted relation, so a stack-scoped token cannot address another stack, e.g. as exercised in the test "an api client scoped to a stack will only see that one stack" for `StacksController#index`.

`CCMenuController` requires `read:stack` permission but redefines `#stack` to bypass this scoping entirely: [2](#0-1) 

`require_permission :read, :stack` only checks that the string `"read:stack"` is present in `ApiClient#permissions`; it never re-validates that `params[:stack_id]` matches `current_api_client.stack_id`, per `ApiClient#check_permissions!`: [3](#0-2) 

Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, any `ApiClient` holding `read:stack` — including one created with a `stack_id` restricting it to a single stack — can retrieve CCMenu status for **any** stack in the installation by simply changing `params[:stack_id]` in the request/URL.

### Impact Explanation
This satisfies the "High" bar of unauthorized read of stack state: an attacker or misused token that is supposed to be limited to reading one stack's status (via `stack_id` scoping) can enumerate/read `lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, and `webUrl` for every other stack in the Shipit instance, escalating outside its granted authorization scope. This is the same class of bug as the reported issue: an authorization decision (`stacks` scoping check) is bound to one field/record, while the actual object acted upon (`stack` in `CCMenuController#show`) is derived independently without re-checking that binding — exactly analogous to `feedFor[currency][base]` being checked while `feedFor[base][currency]` is written independently.

### Likelihood Explanation
Likelihood is high for anyone already holding any valid API token with `read:stack` permission (regardless of whether it is stack-scoped), since exploitation requires only changing a URL parameter (`stack_id`) on a GET request; no additional privilege or credential is required beyond possessing one legitimately-scoped token.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation (as `BaseController#stack` does) instead of `Stack.from_param!` directly, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so stack-scoped `ApiClient` tokens cannot address stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A (this scoping mechanism is exercised in `test/controllers/api/stacks_controller_test.rb` "an api client scoped to a stack will only see that one stack").
2. Authenticate with this token and call `GET /api/<StackA>/ccmenu.xml` — succeeds as expected.
3. Call `GET /api/<StackB>/ccmenu.xml` with the same token, where Stack B is a different stack the token was never scoped to.
4. Because `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`, the request succeeds and returns Stack B's build/lock status, despite the token being authorized only for Stack A.

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
