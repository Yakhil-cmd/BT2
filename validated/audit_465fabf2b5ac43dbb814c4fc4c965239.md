### Title
API `Api::CCMenuController#stack` bypasses per-client stack scoping, letting a stack-scoped token read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts which stacks an `ApiClient` can resolve by scoping the lookup through `stacks` (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`), so a token created with `belongs_to :stack` set is meant to only ever resolve to that one stack. `Api::CCMenuController` overrides the `stack` helper and resolves directly against `Stack.from_param!(params[:stack_id])`, skipping the `stacks` scope entirely, breaking the binding "stack a token authorises" == "stack a token touches".

### Finding Description
`Api::BaseController#stack` is defined as: [1](#0-0) 

This enforces that when an `ApiClient` is created scoped to a specific stack (`belongs_to :stack, optional: true` on `Shipit::ApiClient`, see [2](#0-1) ), any controller resolving `stack` from `params[:stack_id]` can only ever resolve within `Stack.where(id: current_api_client.stack_id)`.

`Api::CCMenuController` however redefines `stack` to bypass this scope: [3](#0-2) 

This calls `Stack.from_param!` on the unscoped `Stack` relation instead of the client-scoped `stacks` relation used everywhere else in the base controller. The route for this action is mounted with the `stack_id` segment taken directly from the request path: [4](#0-3) 

The controller only requires `read:stack` permission (`require_permission :read, :stack`), which any client — including one deliberately scoped down to a single stack via `belongs_to :stack` — can hold: [5](#0-4) 

Test coverage for this controller only exercises the single stack the test client is authorized for, so the missing scope enforcement is not covered: [6](#0-5) 

The equality that should hold is: `stack the client's token authorizes (current_api_client.stack_id)` == `stack the CCMenu endpoint touches (params[:stack_id])`. Because `CCMenuController#stack` skips the `stacks` scoping helper, an attacker holding a valid but stack-restricted token can supply any other stack's `stack_id` in the URL and the equality is broken — the endpoint touches a stack the token was never authorized for.

### Impact Explanation
This grants an unauthenticated-for-that-stack read of stack state: deploy status, last build label/status, activity, and web URL for arbitrary stacks are disclosed to a caller whose token was intentionally scoped to a different, single stack. This matches the "High — unauthenticated read of stack state, task streams or deploy output" impact bucket, since the caller has no read authorization for the disclosed stack.

### Likelihood Explanation
Any holder of a valid, stack-scoped `ApiClient` token (e.g. issued for a CI badge or continuous-integration status widget, a common low-privilege use case per `CCMenuUrlController` which auto-creates such clients with only `read:stack`) can trivially trigger this by changing the `stack_id` path segment. No additional privilege or race condition is required — it is a straightforward authorization bypass reachable with any authenticated API request.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the client-scoped `stacks` relation from `BaseController` instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
Remove the private `stack` override entirely if it is not otherwise necessary, so the base implementation (which enforces `current_api_client.stack_id?` scoping) is used.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_a` only (`ApiClient.create!(stack: stack_a, permissions: ['read:stack'], creator: some_user)`), e.g. as done automatically by `CCMenuUrlController#client` for any user visiting any stack's settings page: `app/controllers/shipit/ccmenu_url_controller.rb:15-18`.
2. Authenticate to the API using that client's `authentication_token`.
3. Issue `GET /api/stacks/<other_owner>/<other_repo>/<other_env>/ccmenu` for `stack_b`, a stack the client was never associated with.
4. Because `Api::CCMenuController#stack` calls `Stack.from_param!` (unscoped) rather than `stacks.from_param!`, the request succeeds with `200 OK` and returns `stack_b`'s CCMenu XML (build status, activity, last build label), despite the token only being authorized for `stack_a`.

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

**File:** app/models/shipit/api_client.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L8-24)
```ruby
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
