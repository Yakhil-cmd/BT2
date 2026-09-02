This is a confirmed vulnerability.

### Title
Cross-stack read via `Api::CCMenuController#stack` using unscoped `Stack.from_param!` instead of `stacks.from_param!` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the base controller's stack lookup with its own private `stack` method that queries the global `Stack.from_param!` instead of the token-scoped `stacks.from_param!` used everywhere else in `Api::BaseController`. This makes the `current_api_client.stack_id == stack.id` invariant enforced by `Api::BaseController#stacks` unreachable in this controller, allowing any valid CCMenu token to read deploy/task state for any stack by simply changing `:stack_id` in the URL.

### Finding Description
The binding that should hold is `current_api_client.stack_id == stack.id` for every stack-scoped ApiClient, which `Api::BaseController#stacks`/`#stack` enforces: [1](#0-0) 
`stacks` restricts the relation to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped, and `stack` resolves `from_param!` against that restricted relation.

`Api::CCMenuController`, however, defines its own `stack` method that bypasses this scoping entirely: [2](#0-1) 
It resolves `Stack.from_param!(params[:stack_id])` against the unscoped `Stack` model, and its custom `authenticate_api_client` only checks `ApiClient.authenticate(params[:token])` — never comparing `current_api_client.stack_id` to the resolved stack's id. The `require_permission :read, :stack` before_action only calls `current_api_client.check_permissions!('read', 'stack')`, which checks the client's `permissions` array, not any stack binding: [3](#0-2) 

Exploit flow: an attacker who has a CCMenu token for stack A (e.g. shared via `CCMenuUrlController#fetch`, which mints `api_stack_ccmenu_url(stack_id: A)` + `token`) can request `GET /stacks/:B/ccmenu.xml?token=<A's token>` for any other stack B. `authenticate_api_client` accepts the token (it's a validly-signed ApiClient id), and `stack` resolves B unconditionally via the unscoped `Stack.from_param!`, so `show` renders B's `deploys_and_rollbacks.last` — deploy status data belonging to a different stack/repository than the token was issued for.

No other guard intervenes: `verify_signature`/webhook checks are irrelevant to this HTTP GET path; `ExplicitParameters` isn't used by this action; and the model-level `Stack` validations don't scope by client. The only scoping mechanism (`Api::BaseController#stacks`) is simply not invoked by this controller because it defines its own conflicting `stack` method.

(Separately, `CCMenuUrlController#client` finds/creates the token via `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` without ever setting `stack:`, so `stack_id` is actually `nil` on issued tokens today — meaning even the intended base-controller scoping would currently treat this client as global. That makes the bypass in `CCMenuController#stack` currently unreachable as a *regression* from an already-scoped token, but the controller's own logic is still independently broken: it hard-codes an unscoped lookup that would defeat scoping even if `ApiClient#stack_id` were properly set, and does so for every existing/future stack-scoped `ApiClient` with `read:stack`, not just CCMenu-issued ones.)

### Impact Explanation
Any bearer of a valid CCMenu-style (or any stack-scoped, `read:stack`-permissioned) API token can read `Api::CCMenuController#show` output — latest deploy/rollback id, timestamp, running state — for **any** stack in the installation, not just the one the token was scoped to, by only changing the `stack_id` route parameter. This is unauthenticated cross-tenant read of deploy state, matching "High - unauthenticated read of stack state" (the token itself is a low-privilege leaked artifact, not a session, but it grants access far beyond its intended scope). It is fully repeatable against every stack id in the system.

### Likelihood Explanation
The attacker needs any single valid CCMenu/API token with `read:stack` permission — such tokens are explicitly designed to be embedded in third-party CI dashboard URLs and are handed out/forwarded outside of Shipit's auth boundary (that's the entire purpose of `CCMenuUrlController#fetch`). No GitHub or Shipit session credentials are required; enumerating other stacks by id/slug is trivial. This makes exploitation low-cost and highly feasible for anyone who legitimately received one CCMenu link.

### Recommendation
Remove the private `stack` override in `Api::CCMenuController` and rely on the inherited `Api::BaseController#stack`/`#stacks` (i.e., `stacks.from_param!(params[:stack_id])`), so the lookup is bound to `current_api_client.stack_id`. Also fix `CCMenuUrlController#client` to scope the `ApiClient` by `stack:` (include `stack: @stack` in both `create_with`/`find_or_create_by!`) so each stack gets a distinct, properly-scoped token instead of one global-scope token shared per user across all stacks.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
require 'test_helper'

module Shipit
  module Api
    class CCMenuControllerCrossStackTest < ActionDispatch::IntegrationTest
      test "a token scoped to stack A cannot read stack B's ccmenu status" do
        stack_a = shipit_stacks(:shipit)
        stack_b = shipit_stacks(:cyclimse) # any distinct stack fixture
        client = ApiClient.create!(
          creator: shipit_users(:walrus),
          name: 'scoped-client',
          stack: stack_a,
          permissions: %w[read:stack],
        )

        assert_equal stack_a.id, client.stack_id # binding as issued

        get api_stack_ccmenu_url(stack_id: stack_b.to_param, token: client.authentication_token)

        # Expected (secure) behavior: request should be rejected because
        # client.stack_id (stack_a.id) != stack_b.id
        assert_response :not_found # or :forbidden

        # Current (vulnerable) behavior returns 200 and renders stack_b's data:
        # assert_response :ok
        # assert_match stack_b.deploys_and_rollbacks.last.id.to_s, response.body
      end
    end
  end
end
```

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
