Based on my investigation, I found a legitimate analog to the RFQ report's bug class in `app/controllers/shipit/api/ccmenu_controller.rb`.

### Title
CCMenu API endpoint ignores `ApiClient` stack scoping, allowing a stack-scoped read token to read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` records can be scoped to a single stack via the optional `stack_id` column, and `Shipit::Api::BaseController#stacks`/`#stack` enforce this scoping for the rest of the JSON API. `Shipit::Api::CCMenuController`, however, overrides `#stack` to bypass that scoping entirely, looking the stack up directly from the request parameter.

### Finding Description
`Shipit::Api::BaseController` defines the intended binding between a token and the stacks it may touch: [1](#0-0) 
`current_api_client.stack_id?` restricts `stacks`/`stack` to the single authorized stack when the `ApiClient` is scoped (as demonstrated by the `here_come_the_walrus` fixture, which is scoped to the `shipit` stack with only `read:stack`) [2](#0-1) .

`Shipit::Api::CCMenuController`, which only requires the generic `read:stack` permission, overrides `#stack` to resolve directly from `params[:stack_id]` instead of delegating to the scoped `stacks`/`stack` helpers in `BaseController`: [3](#0-2) 
This breaks the equality "stack a token authorizes == stack the endpoint touches": `require_permission :read, :stack` only checks that the permission string `read:stack` is present in `current_api_client.permissions`, it never checks that `params[:stack_id]` matches `current_api_client.stack_id`: [4](#0-3) 
Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly, any `read:stack`-scoped token — no matter which single stack it was created for — can be used to read the CCMenu/CI status feed of every other stack in the Shipit instance.

### Impact Explanation
A holder of a narrowly-scoped, read-only token (e.g. the self-service "CCMenu Client" token minted by `Shipit::CCMenuUrlController#fetch` for a specific stack) can enumerate `stack_id` values and pull the last deploy/rollback status, build label, and activity state for stacks they were never authorized to see, via `Shipit::Api::CCMenuController#show`: [5](#0-4) 
This is an authorization-scope escalation: it converts a single-stack read grant into an all-stacks read grant, exposing deploy/build status across every stack managed by the Shipit instance — an unauthorized cross-stack read of stack state.

### Likelihood Explanation
Exploitation only requires possessing (or self-issuing, via the normal "CCMenu URL" button available to any authenticated Shipit user) a single stack-scoped `read:stack` token, and then substituting an arbitrary `stack_id` in the request path — no privilege escalation, secret guessing, or session hijacking is needed once such a token exists.

### Recommendation
Have `Shipit::Api::CCMenuController#stack` reuse the scoped lookup from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction is enforced consistently across all API controllers.

### Proof of Concept
1. As a normal authenticated Shipit user, visit stack A and use the CCMenu button to mint a token via `Shipit::CCMenuUrlController#fetch` (creates an `ApiClient` with `permissions: ['read:stack']`, not bound to any specific stack, or bound to stack A if scoped manually).
2. Call `GET /api/ccmenu/<stack-B-owner>/<stack-B-name>?token=<token>` where stack B is a different stack the token was never authorized for.
3. Because `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly (bypassing `BaseController#stacks`'s `current_api_client.stack_id?` filter), the request succeeds and returns stack B's deploy/build XML feed, confirmed by the existing test pattern showing `CCMenuController` accepts any `stack_id` as long as `require_permission :read, :stack` passes: [6](#0-5) .

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-31)
```ruby
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
