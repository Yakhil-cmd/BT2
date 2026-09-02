### Title
API client stack-scope bypass in `Api::CCMenuController#stack` allows a token scoped to one stack to read deploy status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` binds every API request to the stack(s) an `ApiClient` token is authorized for via the `stacks` helper, which is scoped by `current_api_client.stack_id` when the client is a stack-scoped token. `Api::CCMenuController` overrides the `stack` accessor to bypass this scoping entirely, breaking the equality: *stack a token authorizes == stack the controller acts on*.

### Finding Description
`ApiClient` tokens can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Shipit::Api::BaseController` enforces this scope for every resource lookup through the `stacks`/`stack` helpers: [2](#0-1) 

`require_permission!` only checks that the token's `permissions` array contains `"read:stack"` — it never checks *which* stack the request targets: [3](#0-2) 

`Api::CCMenuController` overrides `stack` to resolve the stack directly against the global `Stack` model instead of the caller's scoped `stacks` relation, and also overrides `authenticate_api_client` to accept the token from a URL query parameter (`params[:token]`) instead of Basic Auth: [4](#0-3) 

The route is nested under the stack-scoped API namespace, so any `stack_id` can be supplied in the path independent of the token's bound stack: [5](#0-4) 

These read-only, single-stack-scoped tokens are actively minted and distributed by the engine itself: `CcmenuUrlController#fetch` creates a fresh `ApiClient` scoped to one specific stack and embeds its `authentication_token` in a URL meant to be shared with CI-status tools (e.g. CCMenu clients embedded in third-party dashboards, IDE plugins, etc.): [6](#0-5) 

Because `Api::CCMenuController#stack` never checks `current_api_client.stack_id`, a holder of one of these narrowly-scoped tokens (designed only to expose one stack's CI badge) can supply an arbitrary `stack_id` in the `/api/stacks/*stack_id/ccmenu` path and receive deploy/task state for a stack it was never authorized to see.

### Impact Explanation
This crosses the "stack a token authorises versus stack it touches" trust boundary explicitly called out as in-scope. It grants **unauthenticated (relative to the target stack) read of stack state and deploy output** for arbitrary stacks in the Shipit instance to any holder of a low-privilege, single-stack, read-only CCMenu token — tokens which are by design widely distributed (embedded in URLs, pasted into third-party CI dashboard tools) and not meant to disclose information about other stacks/repositories. This matches the "High" impact bucket ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
Likelihood is high: CCMenu tokens are routinely generated and shared outside the trusted admin boundary (that is their entire purpose — external CI status widgets). No special privilege beyond possessing any one such token is required; the attacker only needs to change the `stack_id` segment of the URL to enumerate/target other stacks.

### Recommendation
Make `Api::CCMenuController#stack` respect the caller's scope by reusing the base `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so a stack-scoped `ApiClient` can only ever resolve to its own bound stack.

### Proof of Concept
1. Visit any stack's settings page as an authenticated user; this triggers `CcmenuUrlController#fetch`, which creates a new read-only `ApiClient` scoped to `stack_id = shipit_stacks(:shipit).id` and returns a URL containing `?token=<TOKEN_A>` [6](#0-5) .
2. As an attacker who obtains `TOKEN_A` (e.g. from a public CI dashboard configuration), issue:
   `GET /api/stacks/some-other-org/some-other-repo/other-environment/ccmenu?token=<TOKEN_A>`
3. `authenticate_api_client` authenticates `TOKEN_A` successfully [7](#0-6) ; `require_permission :read, :stack` passes because `TOKEN_A`'s permissions include `read:stack` [3](#0-2) ; `stack` resolves to the *other* stack via the unscoped `Stack.from_param!` [8](#0-7) .
4. The response discloses the other stack's latest deploy/rollback status, even though `TOKEN_A` was only ever meant to expose the original stack's CI badge.

### Citations

**File:** app/models/shipit/api_client.rb (L4-9)
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

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
    end
  end
end
```

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** test/controllers/ccmenu_controller_test.rb (L21-33)
```ruby
    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
      end
    end

    test ":fetch url includes api token on query string" do
      get :fetch, params: { stack_id: @stack.to_param }
      data = JSON.parse(response.body)
      client = ApiClient.last
      query = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)
      assert_equal client.authentication_token, query['token']
    end
```
