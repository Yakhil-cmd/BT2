### Title
API token scoped to one stack can read CI status of any stack via CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` bypasses the per-token stack scoping enforced everywhere else in the API, letting a token that is authorized to read only its bound `stack_id` fetch build/deploy status for arbitrary stacks.

### Finding Description
Every other API controller resolves the target stack through `Api::BaseController#stack`, which is scoped by `stacks`: [1](#0-0) 
`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the `ApiClient` has a `stack_id` (i.e., it is a scoped token, as shown by the `here_come_the_walrus` fixture bound to a single stack with only `read:stack`) [2](#0-1) . This is the binding the system relies on: *the stack a token authorizes* (`current_api_client.stack_id`) must equal *the stack the request touches* (`params[:stack_id]`).

`Api::CCMenuController`, however, overrides `stack` to resolve directly from the global `Stack` scope, discarding that binding entirely: [3](#0-2) 

The controller only enforces `require_permission :read, :stack` [4](#0-3) , and `check_permissions!` merely checks that the string `"read:stack"` is present in the client's `permissions` array — it never compares `stack_id` against the requested stack: [5](#0-4) 

So a client created with `permissions: ['read:stack']` and `stack: shipit` (intended to read only the "shipit" stack) satisfies `require_permission :read, :stack` for *any* `stack_id` in the URL, because `CCMenuController#stack` no longer filters by `current_api_client.stack_id`. The test suite for this controller never exercises cross-stack access with a stack-scoped client — it only tests the unscoped `spy` client and a 403-on-no-permissions case, missing the authorization bypass [6](#0-5) , which is why this diverges from the equivalent, correctly-scoped `StacksController#index` test that does validate stack-scoping [7](#0-6) .

The controller also accepts the token via a plain query-string parameter, which is convenient for the CCTray/CI-status use case but makes exploitation trivial (no header manipulation needed): [8](#0-7) 

### Impact Explanation
This is an authorization-scope escalation: any holder of a legitimately-issued, narrowly-scoped `read:stack` API token (bound to a single stack) can read CI/deploy status — name, last build status, last build label, last build time, web URL — of **every** stack in the Shipit instance, including stacks/repositories they were never granted access to. This is an unauthenticated-for-that-resource read of stack state, matching the "High - unauthenticated read of stack state" impact category, since the requesting entity is authorized for a *different* stack, not the one it is now reading.

### Likelihood Explanation
Likelihood is high: exploitation requires nothing beyond an ordinary, already-issued `ApiClient` token scoped to any single stack (a routine, low-privilege credential many CI/build-status integrations hold), and a single unauthenticated GET request with a different `stack_id` in the path. No race conditions, no privileged access, and no additional credentials are needed.

### Recommendation
Make `Api::CCMenuController#stack` reuse the scoped resolution from the base controller instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that a stack-scoped token can never resolve a stack outside its `stack_id`, restoring the same binding enforced in `TasksController`, `CommitsController`, and `StacksController`.

### Proof of Concept
1. Seed two stacks: `stack_A` (private) and `stack_B` (target belongs to a different repo/environment).
2. Create an `ApiClient` scoped to `stack_A` only, with `permissions: ['read:stack']` (mirrors the `here_come_the_walrus` fixture) [2](#0-1) .
3. As this client, issue: `GET /api/ccmenu/<stack_B_repo>/<stack_B_env>.xml?token=<here_come_the_walrus_token>`.
4. `require_permission :read, :stack` passes because the client's `permissions` array contains `read:stack` regardless of which stack is requested [5](#0-4) .
5. `stack` resolves `stack_B` via unscoped `Stack.from_param!` [9](#0-8) , and the response renders `stack_B`'s CI project XML (name, lastBuildStatus, etc.), even though the token was only ever authorized for `stack_A`.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-18)
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
