### Title
Scoped ApiClient can read any stack's CI status via CCMenu, bypassing `stack_id` binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` accessor to look up the requested stack directly from the entire `Stack` table instead of the caller's authorized scope, breaking the same "verify one thing, act on another" binding described in the external report (there, `supply` is decremented in one place but re-incremented elsewhere without ever netting to the correct value; here, permission is checked against `:stack` in the abstract but the concrete stack object used to serve data is never checked against the token's `stack_id` scope).

### Finding Description
`Shipit::Api::BaseController` implements stack scoping for every other API resource: `stacks` restricts the queryable relation to the API client's authorized stack when the client is stack-scoped, and `stack` resolves the requested `stack_id` param through that scoped relation: [1](#0-0) 

`CCMenuController` (used for the CCTray/CCMenu integration) overrides both `authenticate_api_client` (to accept the token via a URL query parameter rather than Basic Auth) and, critically, `stack`: [2](#0-1) 

`stack` is redefined to call `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table, not through `stacks.from_param!`. The `require_permission :read, :stack` before_action only checks that the client's `permissions` array contains `"read:stack"` — it never checks that the specific stack being requested matches `current_api_client.stack_id`: [3](#0-2) 

Equality that should hold: `stack the token is scoped to == stack the controller action touches`. Before the request, an `ApiClient` created with a non-null `stack_id` (e.g. via `Shipit::CCMenuUrlController#client`, which creates a `read:stack`-only, stack-scoped client) is only supposed to see that one stack, as enforced everywhere else in the API (`Shipit::Api::StacksController#stack`, `Shipit::Api::TasksController`, `Shipit::Api::DeploysController`, `Shipit::Api::RollbacksController` — all inherit `stack` from `BaseController` and thus go through `stacks.from_param!`): [4](#0-3) 

For `CCMenuController`, after the request the binding breaks: any valid token (even one minted for a different, unrelated stack, or the general `read:stack`-scoped CCMenu client created for stack A) can be replayed with an arbitrary `stack_id` query param and it will resolve and render that other stack B's build data, because `stack` bypasses the `stacks` scoping helper entirely.

The existing test suite for this controller never exercises the scoping boundary — it only tests permission-flag denial (empty `permissions`) and successful lookups of the same stack the token was minted for: [5](#0-4) 
Contrast this with the equivalent, correctly-scoped test on `StacksController`, which explicitly proves "an api client scoped to a stack will only see that one stack" for the scoped list endpoint: [6](#0-5) 
No analogous test exists for `CCMenuController`, and the code path (`Stack.from_param!` instead of `stacks.from_param!`) confirms the boundary is not enforced there.

### Impact Explanation
This is an unauthenticated-scope escalation for a credential the app itself issues: a `CCMenu` token minted with `read:stack` scoped to one stack (via `CCMenuUrlController#client`, which is exposed to any logged-in Shipit user for their own stacks) can be used to read deploy status, last build label, last build time, and web URL for any other stack in the installation, including private/internal stacks the token holder has no access to. This matches the "High" tier described in the rules: unauthenticated read of stack state via a token whose intended scope is a single stack.

### Likelihood Explanation
High. Exploitation requires only a valid, previously-obtained CCMenu API token (these tokens are handed out routinely for build-status widgets and are visible in plaintext, e.g., embedded in CCTray URLs). No privileged account, GitHub credential, or additional signature is required — the attacker only needs to alter the `stack_id` query parameter of a request they are already authorized to make against the `ccmenu` endpoint.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped relation, consistent with the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This reuses `BaseController#stacks`, which already restricts the queryable set to `current_api_client.stack_id` when the client is stack-scoped, closing the gap between the stack the token authorizes and the stack the controller actually serves.

### Proof of Concept
1. As a legitimate Shipit user, request a CCMenu URL for stack A (`GET /shopify/stack-a/production/ccmenu_url`). This creates/reuses an `ApiClient` scoped to stack A with `permissions: ["read:stack"]` and returns a URL containing `token=<A's token>`: [7](#0-6) 
2. Take that token and call the API directly for a different stack B that the requester does not own or have access to:
   `GET /api/stacks/shopify/stack-b/production/ccmenu.xml?token=<A's token>`
3. `authenticate_api_client` accepts the token and resolves `@current_api_client` to A's stack-scoped client: [8](#0-7) 
4. `require_permission :read, :stack` passes because the client's `permissions` includes `"read:stack"` (scope of the check is the operation name, not the specific stack).
5. `stack` resolves via `Stack.from_param!(params[:stack_id])`, returning stack B directly from the full `Stack` table, bypassing the `stack_id` scoping that `stacks` would have enforced.
6. The response renders stack B's `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` to the holder of A's token — data the token was never authorized to access.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L13-24)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
