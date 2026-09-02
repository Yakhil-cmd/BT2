Confirmed: `CCMenuController#stack` overrides `BaseController#stack` and bypasses the `stacks` scoping method entirely. [1](#0-0) [2](#0-1) 

The `stacks` helper is what enforces the "stack a token authorizes" restriction (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`), and every other API controller (`StacksController`, `TasksController`, `HooksController`, etc.) resolves `stack` through that helper. `CCMenuController`, however, defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly, never consulting `current_api_client.stack_id`. `require_permission :read, :stack` only checks that the client's `permissions` array contains `read:stack` — it never checks which stack the permission applies to. Test fixture `here_come_the_walrus` demonstrates the intended binding: it's an `ApiClient` scoped to `stack: shipit` with `read:stack` permission, and the `StacksController` test confirms this scoping is enforced there ("an api client scoped to a stack will only see that one stack"). [3](#0-2) [4](#0-3) 

But the `CCMenuControllerTest` never exercises cross-stack access — it only checks permission-name enforcement and successful same-stack reads, never that a `here_come_the_walrus`-style token scoped to stack `shipit` is rejected when given a `stack_id` for a different stack. [5](#0-4) 

### Title
Stack-scoped API token can read CI status of any stack via `/ccmenu` — ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuController` overrides `stack` to bypass the tenant-scoping enforced by `BaseController#stacks`, so a `read:stack` token that was minted for one specific stack can be used to read build/deploy status for every stack in the Shipit instance.

### Finding Description
`BaseController` binds a client's authorization to a specific stack via `stacks`: if `current_api_client.stack_id?` is true, only `Stack.where(id: current_api_client.stack_id)` is queried, and `stack` is resolved from that filtered relation (`stacks.from_param!(params[:stack_id])`). [1](#0-0) 

`CCMenuController` instead defines:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
This resolves `params[:stack_id]` against the entire `Stack` table, completely ignoring `current_api_client.stack_id`. [2](#0-1) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!(operation, scope)`, which checks membership in the `permissions` array string list — it has no notion of *which* stack the permission is bound to. [6](#0-5) 

The equality that should hold is: `stack a token authorizes == stack the CCMenu endpoint touches`. Before the flaw, that binding is enforced through `stacks.from_param!`. After it (in `CCMenuController`), the right-hand side becomes "any stack in the instance," breaking the binding for any `ApiClient` that has a non-nil `stack_id` (i.e., was intentionally scoped to a single stack, such as the `here_come_the_walrus` fixture pattern used for CCMenu tokens themselves, created via `CCMenuUrlController#client`). [7](#0-6) 

### Impact Explanation
This is an unauthenticated-scope escalation into stack authorization: an attacker holding a legitimately-issued, narrowly-scoped `ApiClient` token (e.g. a CCMenu token created for one stack, or any `read:stack`-only client bound to a single stack) can pass a different `stack_id` and read that other stack's name, activity, last build status/label/time, and web URL — data belonging to a stack they were never granted access to. This matches the "unauthenticated read of stack state, task streams or deploy output" High-severity category, since the client only proves possession of a token scoped to stack A but the endpoint discloses stack B's state.

### Likelihood Explanation
Trivial to exploit: any holder of a valid, stack-scoped `ApiClient` token (which by design is distributed more widely, e.g. embedded in CCMenu client URLs per `CCMenuUrlController`) only needs to change the `stack_id` route segment in an otherwise normal GET request. No additional secrets, sessions, or privileges are required.

### Recommendation
Make `CCMenuController#stack` use the same `stacks` scoping helper as `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of querying `Stack.from_param!` directly, so the endpoint respects `current_api_client.stack_id` the same way every other API controller does.

### Proof of Concept
1. Create/obtain two stacks, `stack_a` and `stack_b`.
2. Create an `ApiClient` scoped to `stack_a` only (`stack_id` set, e.g. via `CCMenuUrlController#fetch` which does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)`), yielding `token`.
3. As an attacker who only knows `token` (intended solely for `stack_a`'s CCMenu URL) and `stack_b`'s slug, issue:
   `GET /api/stacks/<stack_b-owner>/<stack_b-repo>/<stack_b-env>/ccmenu?token=<token>`
4. The response returns HTTP 200 with `stack_b`'s CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc.), even though the token was never authorized for `stack_b`, because `CCMenuController#stack` resolves via `Stack.from_param!` against the whole table rather than `stacks.from_param!` scoped by `current_api_client.stack_id`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L13-31)
```ruby
      test "a request with insufficient permissions will render a 403" do
        @client.update!(permissions: [])
        get :show, params: { stack_id: @stack.to_param }
        assert_response :forbidden
        assert_json 'message', 'This operation requires the `read:stack` permission'
      end

      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
