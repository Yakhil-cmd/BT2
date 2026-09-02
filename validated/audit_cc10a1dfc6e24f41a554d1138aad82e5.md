### Title
CCMenu status endpoint bypasses per-stack `ApiClient` scoping, letting a token authorized for one stack read the CI/build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` can be scoped to a single stack (`belongs_to :stack, optional: true`), and every other API controller enforces that scope through `BaseController#stacks`/`#stack`. `Api::CCMenuController`, however, resolves the target stack directly from `Stack.from_param!(params[:stack_id])`, ignoring the client's stack scope entirely. A token that is only supposed to authorize reads of stack A can therefore be replayed against any other stack's CCMenu endpoint.

### Finding Description
`ApiClient#check_permissions!` only validates the coarse `operation:scope` pair (e.g. `read:stack`); the fine-grained "which stack" restriction is implemented separately, by scoping the `Stack` lookup itself: [1](#0-0) 

Every other stack-scoped API controller (`Api::StacksController`, `Api::TasksController`, `Api::CommitsController`, `Api::RollbacksController`, `Api::OutputsController`, `Api::HooksController`) resolves the acted-upon stack through this scoped `stacks`/`stack` helper, so a client whose `stack_id` is set can only ever touch that one `Stack` record - confirmed by the test "an api client scoped to a stack will only see that one stack": [2](#0-1) 

`Api::CCMenuController` breaks this binding. It requires only `read:stack` and resolves the stack independently of the scoped helper: [3](#0-2) 

The equality that should hold is:
`current_api_client.stack_id (the stack the token authorizes) == stack.id (the stack the request actually touches)`

`Api::CCMenuController#stack` (`Stack.from_param!(params[:stack_id])`, line 30) breaks this equality: it derives the target stack purely from the URL parameter, never intersecting it with `current_api_client.stack_id` the way `BaseController#stacks` does. Any `ApiClient` holding `read:stack` - including one deliberately scoped to a single stack via the `stack` association exposed in the API-client management UI - can be pointed at an arbitrary `stack_id` in this controller and receive that other stack's deploy/build status.

### Impact Explanation
This is an authorization-scope escalation: a credential that was explicitly restricted, at creation time, to read the state of one stack instead discloses the CI/deploy status (last deploy id, running/success state) of every stack in the installation. This matches the High-severity class of "escalation into ... unauthenticated/unauthorized read of stack state" - the token holder gains read access to stack state outside the boundary the token was supposed to enforce.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token with `read:stack` permission (which is the least-privileged, most commonly issued permission, and is exactly what `CCMenuUrlController` mints for CI dashboard integrations) can exploit this with a single unmodified GET request, substituting a different `stack_id` in the URL. No additional privilege, write access, or social engineering is required - only possession of a token intended for a single stack.

### Recommendation
Make `Api::CCMenuController#stack` go through the same scoped lookup used elsewhere (`stacks.from_param!(params[:stack_id])`) so the stack is intersected with `current_api_client.stack_id` before being served, consistent with every other stack-scoped API controller.

### Proof of Concept
1. As an authenticated user, generate a CCMenu token for Stack A via `GET /A/ccmenu_url`, which creates/reuses an `ApiClient` with `permissions: ['read:stack']` (see `CCMenuUrlController#client`).
2. Note the token embedded in the returned `ccmenu_url`.
3. Issue `GET /api/stacks/B/ccmenu.xml?token=<token-from-step-1>` for an unrelated Stack B that the token was never associated with.
4. `Api::CCMenuController#stack` resolves Stack B directly via `Stack.from_param!`, bypassing the `current_api_client.stack_id` scoping enforced everywhere else, and the response discloses Stack B's latest deploy/build state.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
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
```
