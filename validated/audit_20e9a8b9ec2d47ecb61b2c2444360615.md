### Title
Stack-scoped API token can read CI/build status of any stack via `CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces a binding between the authenticated `ApiClient` and the stacks it is allowed to touch: when a client is created with `stack_id` set, `stacks` is restricted to `Stack.where(id: current_api_client.stack_id)`, and `stack` is resolved through that restricted relation. [1](#0-0)  `Shipit::Api::CCMenuController` overrides `stack` to resolve directly against the unrestricted `Stack` model instead of the scoped `stacks` relation, breaking the equality "stack a token authorises == stack a token touches". [2](#0-1) 

### Finding Description
`BaseController#stacks` is the single place that enforces per-token stack scoping:
```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

`CCMenuController` declares `require_permission :read, :stack`, which only checks that the token has the `read:stack` permission string — it does not check that the requested `stack_id` matches the token's `stack_id` restriction: `check_permissions!` merely verifies `permissions.include?("read:stack")`. [3](#0-2) 

`CCMenuController` then defines its own `stack` method that bypasses the scoped `stacks` relation entirely and resolves the requested `stack_id` against the full `Stack` table:
```
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [4](#0-3) 

As a result, an `ApiClient` record created with a specific `stack_id` (intended to restrict it to a single stack, as tested for `StacksController#index` — "an api client scoped to a stack will only see that one stack") is not actually confined when hitting the CCMenu endpoint. [5](#0-4)  Supplying a different `stack_id` in `GET /api/stacks/:stack_id/ccmenu.xml` (or via `?token=...` query auth, which this controller also supports) resolves any stack in the instance as long as the token merely has the `read:stack` permission bit.

### Impact Explanation
This is an authorization-scope escape: a token that was deliberately restricted to one stack (e.g., the CCMenu-specific token minted by `CCMenuUrlController#client`, which is created per-stack and handed out as a URL) can be used to read the build/CI status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, project name) of every other stack managed by the Shipit instance, not just the one it was issued for. [6](#0-5)  This breaks the "stack a token authorises versus a stack it touches" trust binding and constitutes unauthorized read access to stack state across repository/environment boundaries that the token holder was not meant to see.

### Likelihood Explanation
Exploitation requires only a valid, low-privilege `ApiClient` token that has `read:stack` (the CCMenu token created automatically for any stack viewer already has this) and knowledge/enumeration of another stack's `to_param` (slug), which is not secret. No additional credentials, GitHub access, or session are needed beyond the token itself, and the request is a simple unauthenticated GET with `?token=`.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped `stacks` relation from `BaseController` (i.e., call `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the per-token `stack_id` restriction is enforced consistently across all API controllers.

### Proof of Concept
1. As an admin, create (or let the app auto-create via `CCMenuUrlController#fetch`) an `ApiClient` scoped to `stack_id: A` with `permissions: ["read:stack"]`.
2. Take that client's `authentication_token` (or the `?token=` URL it generates).
3. Request `GET /api/stacks/:stack_B_slug/ccmenu.xml?token=<token>` where `stack_B` is a different stack the token was never scoped to.
4. Observe the CCMenu XML for `stack_B` is returned successfully, even though `StacksController#index` with the same token would only ever list `stack_A`. [7](#0-6)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
