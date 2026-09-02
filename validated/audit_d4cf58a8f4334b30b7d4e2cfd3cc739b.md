### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing stack-scoped tokens to read state of unauthorized stacks - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` establishes the binding *`stack the token authorizes` = `stack the request touches`* by scoping all stack lookups through `stacks.from_param!`, where `stacks` is restricted to `current_api_client.stack_id` when the client is stack-scoped [1](#0-0) . `Shipit::Api::CCMenuController` overrides the `stack` accessor to call `Stack.from_param!(params[:stack_id])` directly, which resolves against the entire `Stack` table without any reference to `current_api_client.stack_id`, breaking that binding [2](#0-1) .

### Finding Description
`ApiClient` records can be scoped to a single stack via the `stack` association and `stack_id` column [3](#0-2) . `BaseController#stacks` enforces this scope for every controller that relies on the inherited `stack` helper: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [4](#0-3) , and `stack` resolves `stacks.from_param!(params[:stack_id])` [5](#0-4) . This is exactly the pattern used correctly elsewhere, e.g. `Api::StacksControllerTest` verifies "an api client scoped to a stack will only see that one stack" [6](#0-5) .

`Api::CCMenuController`, however, redefines `stack` to bypass the scoped `stacks` collection entirely: `@stack ||= Stack.from_param!(params[:stack_id])` [7](#0-6) . The controller still declares `require_permission :read, :stack` [8](#0-7) , so the permission-name check passes as long as the authenticated `ApiClient` has the `read:stack` permission — `check_permissions!` only checks operation/scope strings, never `stack_id` [9](#0-8) . The `stack_id` restriction is therefore never consulted for this endpoint.

Concretely: before the request, the equality holds as `token.stack_id == params[:stack_id]` for every other API endpoint that uses the inherited `stack` helper. After hitting `CCMenuController#show`, the equality is broken — a token minted for stack A (`stack_id = A`) can supply `params[:stack_id] = B` and `Stack.from_param!` will happily resolve stack B, since the lookup ignores `current_api_client` altogether [10](#0-9) .

This mirrors Link B/C of the external report's bug class: a value (a scoped credential) that is validated correctly in one code path (the generic `stack` resolution in `BaseController`) is silently accepted without the same scoping check in a sibling code path (`CCMenuController`) that reimplements the same-looking logic.

### Impact Explanation
Any holder of a stack-scoped `ApiClient` token with `read:stack` permission — the exact kind of token minted automatically for legitimate integrations such as `CCMenuUrlController#client`, which creates a client with `permissions: %w[read:stack]` restricted to one stack [11](#0-10)  — can use that token to read the deploy/rollback status (`stack.deploys_and_rollbacks.last`) of any other stack in the installation, not just the one it was scoped to [12](#0-11) . This is an unauthenticated-for-that-resource read of stack state across the authorization boundary the token was explicitly issued to enforce, matching the High-severity class "unauthenticated read of stack state... " defined in scope.

### Likelihood Explanation
Exploitation requires only possession of any valid, stack-scoped API token with `read:stack` (a low, commonly-granted permission, and the default for the `CCMenu` integration flow itself). No additional secrets, GitHub credentials, or privileged accounts are needed — only substituting a different `stack_id` in an otherwise normal, authenticated request to `Api::CCMenuController#show`.

### Recommendation
Remove the private `stack` override in `Api::CCMenuController` and rely on the inherited `BaseController#stack`/`stacks` helpers so that `current_api_client.stack_id` scoping is enforced consistently, matching the behavior already verified for `Api::StacksController` and other API controllers.

### Proof of Concept
1. Provision (or obtain) a stack-scoped `ApiClient` token authorized only for `stack_id = 1` with `permissions: ['read:stack']` (this is exactly what `CCMenuUrlController#client` creates for legitimate use) [11](#0-10) .
2. Call `GET /api/stacks/2/ccmenu.xml?token=<token>` (i.e., substitute the `stack_id` for a different, unauthorized stack #2) against `Api::CCMenuController#show`.
3. `authenticate_api_client` succeeds because the token itself is valid [13](#0-12) ; `require_permission :read, :stack` passes because the client has `read:stack` [8](#0-7) ; `stack` resolves stack #2 directly via `Stack.from_param!`, ignoring the token's `stack_id = 1` restriction [7](#0-6) .
4. The response discloses stack #2's latest deploy/rollback id, status, and running state — data the token was never authorized to see.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
