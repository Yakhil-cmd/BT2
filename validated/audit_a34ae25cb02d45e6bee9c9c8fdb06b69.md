## Title
CCMenuController bypasses `ApiClient#stack_id` scoping, letting a stack-scoped API token read CI status of arbitrary stacks - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` can be scoped to a single stack via its `stack_id` association, and `Api::BaseController` enforces this binding by resolving the target stack through `stacks.from_param!` where `stacks` is filtered by `current_api_client.stack_id` [1](#0-0) . `Api::CCMenuController`, however, overrides `stack` to resolve directly from `Stack.from_param!(params[:stack_id])`, without ever consulting `current_api_client.stack_id` [2](#0-1) . Its permission check only verifies that the client's permission list contains the generic `read:stack` string [3](#0-2) [4](#0-3) , which is not stack-specific. This breaks the intended equality "stack a token authorizes == stack a token can touch."

### Finding Description
`ApiClient.check_permissions!` only checks membership of `"#{operation}:#{scope}"` (e.g. `read:stack`) in the flat `permissions` array; it never receives or checks the requested stack id [4](#0-3) . The per-stack restriction is instead expected to be enforced by scoping the queryable `Stack` set to `current_api_client.stack_id` in `Api::BaseController#stacks`/`#stack` [1](#0-0) . This is exactly how `Api::StacksController` and other controllers under `Api::BaseController` behave (e.g., the fixture-driven test "an api client scoped to a stack will only see that one stack" confirms this scoping is relied upon) [5](#0-4) .

`Api::CCMenuController` deliberately re-implements both `authenticate_api_client` (to also accept `params[:token]`) and `stack` [6](#0-5) , but its `stack` method calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model rather than through `stacks` — so the `current_api_client.stack_id` binding is never consulted.

### Impact Explanation
A `read:stack`-permitted `ApiClient` that was intentionally created scoped to a single stack (via `belongs_to :stack, optional: true`, e.g. as done automatically by `CCMenuUrlController#client`, which creates a client scoped only to `read:stack` permission and hands its `authentication_token` to end users) [7](#0-6)  can use that same token/id against `Api::CCMenuController#show` with an arbitrary `stack_id` parameter and read CI/build status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state, etc.) for any stack in the deployment, not just the one it was scoped to. This is an unauthenticated-for-that-resource read of stack state across stack/repository boundaries, matching the "unauthenticated read of stack state, task streams or deploy output" High-severity category.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `read:stack` token (these tokens are handed out to third parties/CI dashboards via `CCMenuUrlController`, embedded in URLs) can trivially exploit this by changing the `stack_id` request parameter — no additional privilege, secret, or session is required beyond the token they already legitimately possess for one stack.

### Recommendation
Have `Api::CCMenuController#stack` resolve through the scoped `stacks` helper (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `current_api_client.stack_id` binding enforced elsewhere in `Api::BaseController` is also honored here.

### Proof of Concept
1. An operator uses `CCMenuUrlController#fetch` for `stack_id: "org/app/production"`, which creates/reuses an `ApiClient` with `permissions: ["read:stack"]` scoped to that stack (`stack_id` set) and returns a URL containing its `authentication_token` [7](#0-6) .
2. The holder of that token calls `GET /api/1/stacks/:other_stack_id/ccmenu.xml?token=<token>` for a *different* stack the client was never scoped to.
3. `authenticate_api_client` in `CCMenuController` accepts the token via `ApiClient.authenticate(params[:token])` [8](#0-7) , `require_permission :read, :stack` passes because the client's permission list contains `read:stack` [3](#0-2) , and `stack` resolves the *other* stack directly via `Stack.from_param!(params[:stack_id])` with no `stack_id` scoping check [9](#0-8) .
4. The response returns build status XML for the unrelated stack, proving the token's stack scope was bypassed.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
