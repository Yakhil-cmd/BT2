### Title
CCMenu API endpoint bypasses `ApiClient` stack-scope binding, allowing a stack-scoped token to read the build/deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method to bypass the stack-scoping mechanism that every other API controller relies on, breaking the binding "the stack an `ApiClient` token authorizes == the stack it touches." A CI-status token minted specifically for one stack (via `CCMenuUrlController`) can be replayed against any other stack's `stack_id` to read that stack's latest build/deploy status.

### Finding Description
`Shipit::Api::BaseController` enforces per-token stack scoping through two cooperating methods: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the token is scoped, and `stack` resolves `params[:stack_id]` only within that restricted relation. `Api::StacksController` and `Api::HooksController` rely on this same `stack`/`stacks` pair.

`Api::CCMenuController`, however, defines its own private `stack` method that ignores `stacks` entirely and resolves the parameter directly against the full `Stack` table: [2](#0-1) 

The only authorization gate on this action is `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`: [3](#0-2) 

This only checks that `read:stack` is in the token's permission list - it never checks `stack_id`. Scope enforcement is entirely delegated to the `stack`/`stacks` helper, which `CCMenuController` does not use.

This is the direct analog of the reported bug class: the code path (`fillLPOrder` / here, `CCMenuController#show`) proceeds using a field (`targetMarketID` / here, `params[:stack_id]`) that was never validated against the entity the caller's credential is actually bound to (the null/default market / here, an unscoped `Stack.from_param!` lookup), because the "authorization" check (`RewardStyle == Upfront` due to default zero value / here, `require_permission :read, :stack`) doesn't cover that field.

`CCMenuUrlController` is the intended, narrowly-scoped consumer of this design - it mints an `ApiClient` and expects the resulting URL/token to only ever be usable for the one stack it was generated for: [4](#0-3) 

Note: as read, `CCMenuUrlController#client` does not even set `stack:` on the created `ApiClient` (it only sets `permissions: %w[read:stack]`), which would already make the token globally scoped by the `stacks` helper's own logic (`current_api_client.stack_id?` is false) - but that is a separate concern from the `CCMenuController` bypass, which affects even explicitly stack-scoped tokens (e.g. fixtures like `here_come_the_walrus`, which is scoped to a single stack) as shown by the test suite: [5](#0-4) 

That test proves the scoping mechanism works correctly for `StacksController`, but `CCMenuController` has no equivalent test asserting scope restriction - only permission-based tests exist: [6](#0-5) 

### Impact Explanation
Any bearer of a stack-scoped `read:stack` token (which per the `here_come_the_walrus` fixture pattern is designed to be limited to a single stack) can enumerate and read the CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock status) of every stack in the Shipit instance by supplying a different `stack_id` in the URL, e.g. `/api/stacks/other-owner/other-repo/production/ccmenu?token=<scoped-token>`. This is an unauthorized cross-stack information disclosure: the token authorizes one stack but the endpoint lets it touch any stack. Per the engine's own severity rubric, this is a High-severity finding ("unauthenticated read of stack state ... using a token that should not have access").

### Likelihood Explanation
Any actor already holding a legitimately-issued, narrowly-scoped `ApiClient` token (e.g., one distributed to an external CI dashboard via `CCMenuUrlController#fetch`, or any `ApiClient` created through the `api_clients` UI with `stack_id` set and `read:stack` permission) can trivially exploit this by changing the `stack_id` route segment - no additional privilege or secret is required beyond the token they already legitimately possess.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to reuse the inherited scoped lookup instead of `Stack.from_param!` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
(i.e., delete the private override so the `Api::BaseController#stack`/`#stacks` scoping applies), and add a regression test asserting that a stack-scoped `ApiClient` receives a 404/`RecordNotFound` when requesting a `stack_id` outside its scope on the CCMenu endpoint. Additionally, review `CCMenuUrlController#client` to confirm the created `ApiClient` is scoped with `stack:` as intended.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to stack A with `permissions: ['read:stack']` (e.g. via `CCMenuUrlController#fetch` on stack A, or the `here_come_the_walrus` fixture).
2. Send `GET /api/stacks/<owner>/<repo-B>/<env-B>/ccmenu?token=<token-scoped-to-A>` where repo-B/env-B is a different, unrelated stack B.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `stacks`, which would have restricted the client to stack A), the request resolves stack B and returns its `lastBuildStatus`/`lastBuildLabel`/activity in the XML response, despite the token never being authorized for stack B.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
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
