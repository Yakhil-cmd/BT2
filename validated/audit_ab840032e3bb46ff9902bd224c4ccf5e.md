### Title
Stack-scoped API tokens can read the CCMenu build status of any other stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the base `stack` accessor to resolve the target stack directly from `Stack.from_param!(params[:stack_id])` instead of going through the base controller's client-scoped lookup. This breaks the intended binding: `ApiClient#stack_id` (the stack a token is authorized for) == `stack_id` (the stack a request actually touches).

### Finding Description
`Api::BaseController` enforces token scoping through the `stacks`/`stack` helpers: when an `ApiClient` has a `stack_id`, lookups are restricted to `Stack.where(id: current_api_client.stack_id)` before resolving the requested `params[:stack_id]`. [1](#0-0) 

`Api::CCMenuController`, however, defines its own private `stack` method that bypasses this scoping entirely and resolves any stack from the raw `params[:stack_id]`: [2](#0-1) 

Authorization on this controller is enforced only via `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`, a generic check that the client's `permissions` array contains `"read:stack"` — it has no notion of *which* stack the token is scoped to. [3](#0-2) 

The equality the codebase intends to hold for scoped clients is `current_api_client.stack_id == requested stack.id` (enforced by `stacks` in the base controller). `CCMenuController#stack` never touches `current_api_client.stack_id`, so any client holding a token with `read:stack` permission — including a token created and scoped to one specific stack — can request `GET /api/stacks/:stack_id/ccmenu.xml?token=...` for a **different** `stack_id` and receive that other stack's CCMenu payload (name, last build status/label/time, activity, web URL).

The test suite for this endpoint only exercises the unscoped `spy` fixture client and never verifies stack-scoping is honored, which is consistent with this scoping gap going unnoticed. [4](#0-3) 

This class of bug — a value that is supposed to be constrained to zero/matching but silently diverges because a code path skips the invariant check — mirrors the reported issue: the "stack a token authorises" and "the stack it touches" should be equal, but one code path (`CCMenuController#stack`) never enforces that equality.

### Impact Explanation
This is an authorization-scope bypass: a token deliberately restricted to one stack (e.g., embedded in a CI status badge URL, a common intended use of `CCMenuUrlController`/CCMenu integration) can be used to read build/deploy status of any other stack in the Shipit instance, including private/locked stacks, without needing the intended stack-specific token. This is a cross-stack unauthorized read of stack state, matching the High-impact category of "unauthenticated/unauthorized read of stack state ... or deploy output."

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped, `read:stack`-permissioned API token (which by design is meant to be shared more broadly, e.g. embedded in CI dashboard URLs or badges) can trivially exploit this by changing the `stack_id` path/query parameter — no additional privilege, secret, or session is required beyond possessing one such token.

### Recommendation
Have `Api::CCMenuController#stack` use the same client-scoped resolution as the base controller (i.e., delegate to `stacks.from_param!(params[:stack_id])`, or explicitly verify `current_api_client.stack_id.nil? || current_api_client.stack_id == resolved_stack.id`) instead of calling `Stack.from_param!` directly.

### Proof of Concept
1. An admin creates an `ApiClient` scoped to `stack_A` with `permissions: ["read:stack"]` (as `ApiClient` supports `belongs_to :stack, optional: true`), intending the token to only expose `stack_A`'s CCMenu status. [5](#0-4) 
2. Anyone in possession of this token (e.g. it is embedded in a public CI status widget URL for `stack_A`) issues:
   `GET /api/stacks/<stack_B_id>/ccmenu.xml?token=<stack_A_token>`
3. `authenticate_api_client` authenticates the token successfully (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the token has `read:stack` in its permissions list, and `stack` resolves `stack_B` via `Stack.from_param!(params[:stack_id])` — ignoring that the token's `stack_id` is `stack_A`. [6](#0-5) 
4. The response renders `stack_B`'s CCMenu XML (name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`), which the token was never authorized to view.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-31)
```ruby
# frozen_string_literal: true

require 'test_helper'

module Shipit
  module Api
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

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
