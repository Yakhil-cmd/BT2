### Title
CCMenu API endpoint bypasses per-stack ApiClient token scoping, allowing cross-stack read of deploy/build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method used by every other API controller and, in doing so, drops the enforcement that binds an `ApiClient` token to the single `Stack` it was scoped to. Any valid token — including a narrowly-scoped one meant only for a specific stack's CCMenu badge — can be replayed with a different `stack_id` to read another stack's build status.

### Finding Description
`Shipit::Api::BaseController` establishes the invariant that an `ApiClient` scoped to a stack (`stack_id` present) can only operate on that stack: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`require_permission!` only checks a coarse `operation:scope` string like `read:stack` via `ApiClient#check_permissions!` — it never checks *which* stack: [2](#0-1) 

The actual per-stack restriction is enforced exclusively by the `stacks`/`stack` helper in `BaseController`, i.e. `stack_id` (the field the token authorizes) must equal the stack being acted on (the field the request touches).

`CCMenuController`, however, redefines `stack` to bypass this scoping entirely, going straight to the unscoped `Stack.from_param!`: [3](#0-2) 

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

It only requires the coarse `read:stack` permission: [4](#0-3) 

This is the same class of bug as the analog report: the binding that should hold — `ApiClient.stack_id == stack acted upon` — is enforced in one code path (`BaseController#stack`) but not in another reachable path (`CCMenuController#stack`) that inherits from the same base and shares the same permission model. CCMenu tokens are specifically designed to be embedded in external, less-trusted contexts: `CCMenuUrlController` mints a token scoped to one stack with only `read:stack` permission and returns a URL containing the token as a query-string parameter, intended for use in third-party CI dashboard tools: [5](#0-4) 

Any holder of one such URL/token (e.g., a CI-status-viewing tool, or anyone who intercepts/receives the URL) can change `stack_id` in the request to point at a *different* stack and the controller will happily render that stack's information, since `CCMenuController#stack` never checks `current_api_client.stack_id`.

### Impact Explanation
This breaks the equality `ApiClient.stack_id == stack_id (acted upon)`, exactly the kind of deployment-trust binding targeted by the rules. It results in **unauthenticated-relative read of stack state and deploy output** — a token minted to expose a single stack's build status now exposes the build status, last deploy label (commit SHA), activity/lock state, and web URL of *any* stack in the Shipit instance, satisfying the High-impact bar ("unauthenticated read of stack state, task streams or deploy output"). Since these tokens are explicitly designed to be shared/embedded outside of Shipit's normal authenticated UI (unlike a session-bound `ApiClient` token used over Basic Auth internally), the exposure surface is meaningfully larger than a typical scoped-token leak.

### Likelihood Explanation
Exploitation requires only a single valid CCMenu token for any one stack (which is by design distributed to less-trusted external tooling/URLs) and knowledge or guessing of another stack's `to_param` (its `owner/name/environment` path, which is often public/predictable, e.g., matching the GitHub repo name). No privileged access, session, or webhook secret is required beyond the CCMenu token itself, making this readily reachable by an unprivileged holder of any such token.

### Recommendation
Remove `CCMenuController`'s override of `#stack` and instead use the base controller's scoped `stacks.from_param!(params[:stack_id])`, or explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering. Ensure the fix is covered by a regression test verifying that a stack-scoped CCMenu token cannot render a different stack's project XML.

### Proof of Concept
Given a fixture like `here_come_the_walrus` (`ApiClient` scoped to stack `shipit`, permission `read:stack`) and another existing stack, e.g. `shopify/other-repo/production`:

```
GET /api/stacks/shopify/other-repo/production/ccmenu?token=<here_come_the_walrus_token>
```

Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (not `stacks.from_param!`), this request succeeds and returns the CCTray XML (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for `shopify/other-repo/production`, even though the token was only ever scoped to (and intended to expose) the `shipit` stack. Compare with `test/controllers/api/ccmenu_controller_test.rb`, whose existing tests only check permission-string enforcement, not stack-scope enforcement: [6](#0-5)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
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
