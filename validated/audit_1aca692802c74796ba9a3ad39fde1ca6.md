Confirmed: `Shipit::Api::StacksController` uses the scoped `stacks` helper (`stacks.from_param!`), which is verified by the test "an api client scoped to a stack will only see that one stack" [1](#0-0) , backed by `BaseController#stacks`/`#stack` [2](#0-1) . `Shipit::Api::CCMenuController`, however, overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped model, bypassing the `current_api_client.stack_id` restriction entirely [3](#0-2) . The `require_permission :read, :stack` before_action only checks that `"read:stack"` is present in the token's permission list via `ApiClient#check_permissions!`, without checking the specific stack instance [4](#0-3) . This satisfies the "a stack a token authorises versus a stack it touches" binding-break pattern called out in the rules.

### Title
Stack-Scoped API Token Can Read Any Stack's Build Status via CCMenu Endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` bypasses the stack-scoping enforced everywhere else in the API by resolving the stack directly from `Stack.from_param!` instead of the `stacks` helper that filters by `current_api_client.stack_id`.

### Finding Description
Every other `Shipit::Api::BaseController` subclass resolves the current stack through `stacks.from_param!(params[:stack_id])`, where `stacks` is `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [2](#0-1) . This ties the stack an `ApiClient` token can act on to the `stack_id` it was issued for, so a stack-scoped `ApiClient` (e.g., created via `CCMenuUrlController#client`, which builds a token scoped to a single stack with `read:stack` permission [5](#0-4) ) cannot read state for other stacks.

`Shipit::Api::CCMenuController` overrides this by redefining `#stack` to call `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` model [3](#0-2) , completely ignoring `current_api_client.stack_id`. The `require_permission :read, :stack` check only verifies the permission string `"read:stack"` is present in the client's permission list, not that the requested stack matches the client's `stack_id` [4](#0-3) .

As a result, the equality the system is supposed to enforce — "stack authorised by token" == "stack touched by the request" — is broken specifically in this controller: any token carrying `read:stack` (whether globally scoped or scoped to a completely different stack) can be replayed against `/api/stacks/:stack_id/ccmenu` for **any** stack in the installation by simply changing the `stack_id` path segment or `token` query parameter, since `CCMenuController#authenticate_api_client` also accepts the token from `params[:token]` rather than only the `Authorization` header [6](#0-5) .

### Impact Explanation
This allows a holder of any single-stack CCMenu token (which is routinely embedded in CI dashboard tools such as CCMenu-compatible clients, per `CCMenuUrlController`) to enumerate and read build status, latest deploy id, activity, and status for every other stack managed by the Shipit instance, not just the one it was provisioned for. This is an unauthorized read of stack state across repository/stack boundaries by a credential that was only ever meant to be scoped to one stack, matching the "unauthenticated read of stack state" / cross-scope escalation impact bucket.

### Likelihood Explanation
Exploitation requires only a valid `ApiClient` token with `read:stack` permission (any such token, including ones intentionally scoped to a single stack for embedding in a status-monitor URL, as shown by `CCMenuUrlController`). No privileged account or additional credential is needed beyond a token that is expected to be narrowly scoped and often distributed to lower-trust consumers (CI dashboards). This makes the likelihood high once any such token leaks or is intercepted by its intended narrow-scope consumer.

### Recommendation
Remove the `#stack` override in `Shipit::Api::CCMenuController` and use the inherited `BaseController#stack`, which resolves through the scoped `stacks` collection, so the `current_api_client.stack_id` restriction is honored consistently with the rest of the API surface.

### Proof of Concept
1. As a Shipit admin, create a CCMenu-style API client scoped to `stack_id: A`, e.g., through `CCMenuUrlController#client` for stack A, and obtain `authentication_token`.
2. Note stack B exists and belongs to a different repository/environment.
3. Issue `GET /api/stacks/<stack_B_path>/ccmenu?token=<token_for_stack_A>`.
4. Because `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks` collection, the request succeeds and returns stack B's build status XML, even though the token was only ever authorized for stack A.

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
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
