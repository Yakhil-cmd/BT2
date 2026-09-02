## Finding

The vulnerability class here — "a value the contract trusts to compute an outcome differs from the value actually used to move funds" — maps onto Shipit's `ApiClient` stack-scoping mechanism: the token authorizes actions against a specific `stack_id`, but `Api::CCMenuController` resolves the target `Stack` through a path that ignores that scope.

### Root cause

`Api::BaseController` establishes a binding between an `ApiClient` and the `Stack`(s) it may touch: [1](#0-0) 

`stacks` returns only `current_api_client.stack_id` when the client is scoped, and `stack` is derived from that scoped relation (`stacks.from_param!`). Every other API controller (`StacksController`, `CommitsController`, `TasksController`, etc.) relies on this `stack`/`stacks` helper, which is why a stack-scoped `ApiClient` "will only see that one stack" (as asserted by the existing test suite): [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to bypass the scoped relation entirely and resolve any stack directly via `Stack.from_param!`: [3](#0-2) 

`require_permission :read, :stack` only checks that the token carries the string permission `read:stack` in its `permissions` array — it never checks `stack_id` against the requested stack: [4](#0-3) 

So the binding that should hold — *"stack a token authorizes" == "stack it touches"* — breaks specifically in this controller. A token minted with `stack_id` set to Stack A (e.g., issued for a single project's CI dashboard/badge integration) still has the global `read:stack` permission entry, and can therefore be replayed with any other `stack_id` param to read deploy/build status (`lastBuildStatus`, `lastBuildLabel`, running state, lock reason) for stacks it was never scoped to.

### Confirming the gap

The `CCMenuController` test suite exercises the unscoped/global client (`authenticate!`) and never exercises a stack-scoped client (`here_come_the_walrus`, used elsewhere to prove per-stack isolation) against a *different* `stack_id`: [5](#0-4) 

Compare with `StacksControllerTest`, which explicitly proves scoping is enforced there via the shared `stacks` helper: [6](#0-5) 

### Impact

This satisfies the "High — unauthenticated/unauthorized read of stack state, task streams or deploy output" bar: an attacker holding only a narrowly-scoped `ApiClient` token (e.g., embedded in a public CI-status badge URL, which is the exact intended low-trust use case for CCMenu tokens) can enumerate/read build and lock status of arbitrary other stacks in the installation, defeating the `stack_id` isolation the token was explicitly issued with.

### Recommendation
`Api::CCMenuController#stack` should resolve through the scoped `stacks` relation (as in `BaseController`) instead of `Stack.from_param!`, so a stack-scoped `ApiClient` cannot query stacks outside its `stack_id`. [7](#0-6)

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

**File:** test/controllers/api/stacks_controller_test.rb (L188-198)
```ruby
      test "#index returns a list of stacks filtered by repo and api client" do
        authenticate!(:here_come_the_walrus)

        repo = shipit_repositories(:soc)

        get :index, params: { repo_owner: repo.owner, repo_name: repo.name }
        assert_response :ok
        assert_json do |stacks|
          assert_equal 0, stacks.size
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-32)
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
