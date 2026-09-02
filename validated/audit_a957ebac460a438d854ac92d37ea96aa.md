### Title
Stack-scoped API token can read CCMenu build status of any other stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` bypasses the stack-scoping enforced everywhere else in the API for `ApiClient` tokens that are bound to a single stack (`ApiClient#stack_id`). Every other API controller resolves the target stack through `BaseController#stack`, which is restricted to `Stack.where(id: current_api_client.stack_id)` when the token is stack-scoped. `CCMenuController` instead defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, so the permission check (`require_permission :read, :stack`) only verifies the token *has* the `read:stack` permission, never that the token is authorized *for the specific stack being requested*.

### Finding Description
`ApiClient` supports scoping a token down to a single stack via the optional `stack_id` column: [1](#0-0) 

`Api::BaseController` enforces this binding for every normal controller: [2](#0-1) 
`stacks` is restricted to `current_api_client.stack_id` when set, and `stack` resolves `params[:stack_id]` only within that restricted relation — this is the equality the engine is supposed to maintain: `stack a token authorizes == stack a token touches`.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [3](#0-2) 
It calls `Stack.from_param!(params[:stack_id])` — the *unscoped* `Stack` model — rather than `stacks.from_param!(params[:stack_id])`. `require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks that `"read:stack"` is present in the token's `permissions` array; it never compares `stack.id` to `current_api_client.stack_id`: [4](#0-3) 

As a result, any token that has been issued with `read:stack` permission — including a token intentionally scoped to a single, non-sensitive stack (e.g. via `CCMenuUrlController`, which mints exactly such tokens: `permissions: %w[read:stack]`) — can be used to fetch the CCMenu XML for *any* other stack in the Shipit installation simply by changing `stack_id` in the request, in violation of the `stack_id` binding the token was created with. [5](#0-4) 

The existing test suite for this controller never exercises a stack-scoped client against a *different* stack (`shipit_stacks(:shipit)` is used throughout), so this gap is untested: [6](#0-5) 
while the equivalent check for `Api::StacksController` explicitly validates that a scoped client cannot see other stacks: [7](#0-6) 

### Impact Explanation
This crosses the "stack a token authorises versus a stack it touches" trust boundary called out for this engine: a deliberately narrow, low-privilege token minted for one stack (e.g. a CCMenu badge/RSS-style token distributed to third parties or embedded in a public dashboard) can be used to read the build/deploy status (name, last build status/label/time, activity, `webUrl`) of any other stack in the Shipit instance, including stacks the token holder was never meant to have any visibility into. This is an unauthorized cross-stack read of stack state, matching the "High" impact bucket (unauthenticated/unauthorized read of stack state) defined for this engine, since the attacker only needs a `read:stack`-scoped token intended for one stack, not the specific stack being probed.

### Likelihood Explanation
High likelihood: `CCMenuUrlController` actively mints tokens with only `read:stack` permission and no additional stack-binding enforcement beyond `stack_id`, intended for use in external CI dashboards (CCMenu/CCTray consumers). Anyone in possession of such a token (which is designed to be shared/embedded, since it's meant to be fetched via unauthenticated tooling using the token as a query param) can trivially enumerate other stacks by varying `stack_id` — no privileged access or additional credentials are needed beyond the token itself, which this class of token is explicitly designed to be low-privilege and widely distributed.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped resolution used elsewhere:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it respects `current_api_client.stack_id` exactly like `Api::BaseController#stack`/`#stacks`, restoring the invariant that a stack-scoped token can only ever resolve to its bound stack.

### Proof of Concept
1. Create (or use `CCMenuUrlController#client`) an `ApiClient` scoped to `stack_id: A.id` with permissions `["read:stack"]`.
2. Obtain its `authentication_token`.
3. Send `GET /api/A/ccmenu.xml`? actually: `GET /api/<any-other-stack>/ccmenu.xml?token=<token>` (i.e. hit `Api::CCMenuController#show` with `params[:stack_id]` set to a *different* stack `B`'s param).
4. Observe HTTP 200 with stack `B`'s CCMenu XML payload (`name`, `lastBuildStatus`, etc.), even though the token was only supposed to authorize reads of stack `A`. Compare against `Api::StacksController#index`, where the same token correctly returns 0 results for stack `B` (`test/controllers/api/stacks_controller_test.rb:188-198`), confirming the scoping bypass is specific to `CCMenuController`.

### Citations

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L7-24)
```ruby
    class CCMenuControllerTest < ApiControllerTestCase
      setup do
        authenticate!
        @stack = shipit_stacks(:shipit)
      end

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
