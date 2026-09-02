### Title
`Api::CCMenuController#stack` bypasses per-client `stack_id` scoping by querying `Stack` directly instead of the scoped `stacks` relation - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the private `stack` finder to call `Stack.from_param!(params[:stack_id])` directly [1](#0-0)  instead of using the `stacks` helper (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) that `Api::StacksController` and `Api::DeploysController` use for their own `stack` finders [2](#0-1) [3](#0-2) . As a result, an `ApiClient` that was issued with a specific `stack_id` (intended to scope it to one stack) can use its token against the CCMenu endpoint to read the build status of *any* stack, not just the one it is bound to.

### Finding Description
Broken binding: for stack-scoped clients, `current_api_client.stack_id` should equal (or the request's `stack_id` should be contained in) the set of stacks resolvable by that client, i.e. `resolved_stack ∈ stacks_scoped_to(current_api_client)`. In `StacksController#stack` and `DeploysController#index`/`#create` this holds because `stack` is built from `stacks.from_param!(...)`, which filters by `current_api_client.stack_id` when present [2](#0-1) . In `CCMenuController`, the overridden `stack` method calls `Stack.from_param!(params[:stack_id])` on the unfiltered `Stack` relation, so `resolved_stack` is not constrained to `current_api_client.stack_id` at all [1](#0-0) .

`require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)`, which checks the client's `permissions` array (e.g. `read:stack`) but never looks at `stack_id` or the requested `stack_id` param at all [4](#0-3) [5](#0-4) . The only place stack-level scoping is enforced elsewhere is the `stacks` helper — which `CCMenuController` deliberately does not use.

Regarding the query-string token: this is not itself the bug — accepting `params[:token]` for CCMenu is an intentional, tested feature (`"can authenticate with query string token"` in the existing test suite) [6](#0-5) , since CI dashboards/build badges cannot set `Authorization` headers. The real divergence is independent of transport: even via the `Authorization` header a stack-scoped client would hit the same unscoped `Stack.from_param!` call.

Exploit flow: obtain (via any leak vector, e.g. a public badge URL) a token for an `ApiClient` created with `stack_id` set to stack A and permission `read:stack`. Request `/ccmenu.xml?token=<token>&stack_id=<param-for-stack-B>`. `authenticate_api_client` sets `@current_api_client` from the token [7](#0-6) ; `require_permission!` passes because permissions include `read:stack` (no per-stack check) [5](#0-4) ; `stack` resolves stack B unrestricted [1](#0-0) ; `show` renders stack B's build status [8](#0-7) .

### Impact Explanation
An attacker holding any single stack-scoped CCMenu token (leaked from a public badge/dashboard) can read build/deploy status for arbitrary other stacks the token was never intended to access, defeating the per-client `stack_id` scoping mechanism entirely. This is an unauthenticated-for-that-resource read of stack state across tenants/stacks, matching the "unauthorized read of stack state" impact category. It does not expose secrets or allow writes/deploys, and does not require the transport-channel argument in the original hypothesis to be true.

### Likelihood Explanation
Requires possession of one previously issued `ApiClient` token that was created with a `stack_id` restriction and `read:stack` permission — this is a realistic, low-cost precondition since such tokens are specifically designed to be embedded in CCMenu URLs (build badges, CI dashboards) that get logged, cached, or publicly shared. No Shipit session, GitHub credentials, or other secret is needed beyond the leaked token itself.

### Recommendation
Change `CCMenuController#stack` to resolve stacks through the scoped `stacks` helper (i.e. `stacks.from_param!(params[:stack_id])`) exactly like `StacksController`/`DeploysController`, so that clients with a restrictive `stack_id` cannot resolve stacks outside their scope.

### Proof of Concept
```ruby
test "a stack-scoped token cannot read a different stack via ccmenu" do
  other_stack = shipit_stacks(:cyclimse) # a stack different from @client's scoped stack
  @client.update!(stack_id: @stack.id, permissions: ['read:stack'])

  get :show, params: { stack_id: other_stack.to_param, token: @client.authentication_token }

  # Binding under test: resolved stack must belong to the set scoped to current_api_client.stack_id
  assert_not_equal @client.stack_id, other_stack.id
  assert_response :not_found # expected if properly scoped; currently returns 200 with other_stack's data
end
```

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
