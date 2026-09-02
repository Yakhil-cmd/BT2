### Title
Stack-scoped API token can read the CI/build status of any stack via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` may only touch the stack it was scoped to, by resolving `stack` through a `stacks` relation that is filtered to `current_api_client.stack_id`. `Shipit::Api::CCMenuController` inherits `BaseController` but overrides `stack` to bypass that filter, looking the requested stack up globally instead of through the client's authorized scope. This breaks the binding "stack a token authorizes == stack the request touches," letting any valid `read:stack` token read CI/build state for stacks it was never granted access to.

### Finding Description
`BaseController` scopes stack lookups to the authenticated client's authorization: [1](#0-0) 

This means that for every other API controller that relies on `stack`/`stacks` (e.g. `Api::StacksController`, `Api::DeploysController`, `Api::TasksController`), an `ApiClient` created with a `stack_id` (i.e. scoped to one stack, as in the `here_come_the_walrus` fixture) can never resolve a different stack — `Stack.where(id: current_api_client.stack_id).from_param!(...)` raises `RecordNotFound` for any stack other than the one it's bound to.

`CCMenuController`, however, redefines `stack` to skip this scoping entirely and resolve directly against all stacks: [2](#0-1) 

It still calls `require_permission :read, :stack`, but `check_permissions!` only checks that `"read:stack"` is present in `ApiClient#permissions` — it never checks `stack_id`: [3](#0-2) 

So the equality that should hold across the API surface — `current_api_client.stack_id ⇒ only that stack is reachable` — is broken specifically in `CCMenuController#stack`. Any client whose token carries `read:stack` (whether globally scoped or scoped to one specific stack) can pass an arbitrary `stack_id` in the URL and receive that other stack's CCMenu XML.

### Impact Explanation
This is an authorization-scope crossing: an API token that a Shipit admin explicitly restricted to a single stack (via the stack-scoped `ApiClient` creation flow) can be replayed against `GET /api/:other_stack_id/ccmenu.xml` to read another stack's build/CI status, lock state, and last deploy outcome — data the client was never authorized to see. This matches the "unauthorized/unintended read of stack state" impact category: it crosses the stack-authorization boundary that every other API controller in this engine enforces.

### Likelihood Explanation
High. No privileged access is required beyond possessing any valid `ApiClient` token with `read:stack` permission (e.g. a legitimately-issued CCMenu token for stack A, distributed to a build-status widget/tool). The attacker only needs to change the `stack_id` route/query parameter to target a different stack; this is a trivial, deterministic request-level manipulation, not dependent on race conditions, timing, or infrastructure access.

### Recommendation
Make `CCMenuController#stack` reuse the scoped `stacks` relation from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so stack-scoped tokens are constrained to their authorized stack exactly like every other API controller.

### Proof of Concept
1. As an authenticated Shipit user, create a stack-scoped `ApiClient` for Stack A with `permissions: ["read:stack"]` and `stack: <Stack A>` (mirrors the `here_come_the_walrus` fixture in `test/fixtures/shipit/api_clients.yml`).
2. Obtain that client's `authentication_token`.
3. Send `GET /api/<Stack B id-or-slug>/ccmenu.xml?token=<Stack A's token>` for a completely unrelated Stack B that the client was never granted access to.
4. Observe the response returns `200 OK` with Stack B's CI/build status (`lastBuildStatus`, `lastBuildLabel`, lock status, etc.), confirmed by: [4](#0-3) 
which shows the token/`stack_id` combination alone drives the response — with no `stacks` scoping check comparable to `BaseController#stacks`, a token scoped to a different stack still succeeds when pointed at a stack it wasn't issued for.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L26-31)
```ruby
      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
