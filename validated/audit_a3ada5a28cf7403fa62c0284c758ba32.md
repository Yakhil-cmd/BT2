I found a direct analog of this "state assumed but not enforced" binding-break pattern in the API layer: `Api::CCMenuController` overrides the stack-scoping logic from `Api::BaseController`, silently dropping the `ApiClient#stack_id` restriction that is supposed to bind a token to a single stack.

### Title
Unauthorized cross-stack read via CCMenu API token scope bypass - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` scopes stack lookups to the stacks an `ApiClient` is authorized for via `current_api_client.stack_id`, but `Api::CCMenuController` overrides the `stack` accessor with an unscoped lookup, breaking the binding between "stack a token authorizes" and "stack the request actually touches."

### Finding Description
`Api::BaseController` defines the canonical, safe pattern for resolving the target stack from a request: [1](#0-0) 

`stacks` is deliberately restricted to `Stack.where(id: current_api_client.stack_id)` when the authenticated `ApiClient` has a `stack_id` set, i.e., when the token was scoped to a single stack.

`Api::CCMenuController`, however, does not use this helper. It defines its own `stack` method that resolves the stack purely from the request parameter, with no reference to `current_api_client.stack_id` at all: [2](#0-1) 

The only authorization check performed is `require_permission :read, :stack`, declared at the class level: [3](#0-2) 

which calls into `ApiClient#check_permissions!`, a check that only verifies the *permission string* `"read:stack"` is present in the client's permission list — it never checks *which* stack the client is scoped to: [4](#0-3) 

Tokens with this exact shape — narrowly scoped to a single stack with only `read:stack` — are minted automatically and handed out by `CCMenuUrlController`, which creates a stack-scoped, read-only `ApiClient` for CI-status-widget consumption: [5](#0-4) 

The equality that should hold is: `stack the token authorizes (current_api_client.stack_id)` == `stack the request actually touches (params[:stack_id])`. `Api::CCMenuController#stack` breaks this equality by dropping the left-hand side of the check entirely, so any value of `params[:stack_id]` is accepted regardless of the token's `stack_id`.

### Impact Explanation
A holder of a legitimately-issued, narrowly-scoped `read:stack` token (bound to one specific stack, e.g. obtained via the "get CCMenu URL" feature) can supply an arbitrary `stack_id` to `Api::CCMenuController#show` and read the CI/build status (`lastBuildStatus`, `lastBuildLabel`, lock status, activity) of any other stack in the installation — including stacks the token was never meant to expose. This is an unauthorized cross-stack read of stack state, matching the High-severity category "escalation into ... unauthenticated read of stack state, task streams or deploy output" via a credential whose intended authorization boundary (one stack) is bypassed.

### Likelihood Explanation
Any user capable of obtaining a stack-scoped read-only token — which is handed out automatically and without elevated privileges by `CCMenuUrlController#fetch` for the CCMenu integration — can immediately exploit this by changing the `stack_id` query parameter on the `Api::CCMenuController#show` route. No special permission beyond the read-only, single-stack token is required, and the override is a simple, always-reachable code path (no race condition or edge-case timing required).

### Recommendation
Remove `Api::CCMenuController`'s custom `stack` method and rely on the base `stacks`/`stack` helpers from `Api::BaseController` (or explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering), so that CCMenu lookups respect the same per-token stack scoping enforced everywhere else in the API.

### Proof of Concept
1. As any user, visit a stack and use the "CCMenu URL" feature (`CCMenuUrlController#fetch`) to obtain a URL of the form `.../ccmenu.xml?token=<T>`, where `<T>` is an `ApiClient` token scoped (`stack_id`) to Stack A with only `read:stack` permission.
2. Send `GET /api/stacks/:stack_id_of_B/ccmenu.xml?token=<T>` substituting Stack B's identifier in `stack_id` instead of Stack A's.
3. Observe that `Api::CCMenuController#authenticate_api_client` succeeds (the token is valid) and `require_permission :read, :stack` passes (the token has `read:stack`), and the response renders Stack B's CI status/lock state, even though the token was only ever scoped to Stack A. [2](#0-1)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-7)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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
