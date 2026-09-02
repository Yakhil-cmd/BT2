### Title
Stack-scope authorization bypass in CCMenu API endpoint - (`app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `Shipit::Api::CCMenuController` overrides the stack-lookup helper inherited from `Shipit::Api::BaseController` in a way that skips the `ApiClient#stack_id` scoping enforced everywhere else in the API. A `read:stack` token generated for one stack (via the CCMenu URL feature) can be replayed against the `ccmenu` endpoint of *any other stack* in the installation, returning that stack's deploy/build state.

### Finding Description
`Shipit::Api::BaseController` defines the authorization-scoping primitive used by every other API controller: [1](#0-0) 

`stacks` restricts the visible `Stack` set to `current_api_client.stack_id` when the authenticated `ApiClient` is scoped to a single stack, and `stack` (used by `LocksController`, `TasksController`, `DeploysController`, etc.) always resolves through this scoped relation. This is the binding: **stack a token authorizes == stack it can touch**, enforced by `stacks.from_param!(params[:stack_id])`.

`Shipit::Api::CCMenuController`, however, redefines `stack` to bypass the scoped relation entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` class rather than through `stacks`, so `current_api_client.stack_id` is never consulted. The only authorization gate left is `require_permission :read, :stack`, declared as: [3](#0-2) 

but `check_permissions!` only validates the operation/scope *name* (`read:stack`), not which specific stack the token is bound to: [4](#0-3) 

The intended source of stack-scoped `ApiClient` tokens is `Shipit::CCMenuUrlController#fetch`, which mints a `read:stack` client tied to one specific stack for embedding in third-party CI dashboards: [5](#0-4) 

Because `Api::CCMenuController#stack` ignores `current_api_client.stack_id`, any holder of such a token can substitute a different `stack_id` in the URL path and read another stack's deploy status — a stack the token was never meant to authorize.

### Impact Explanation
This breaks the stack-authorization boundary that the rest of the API enforces (`ApiClient.stack_id` scoping). A token minted for a low-sensitivity stack can be used to read deploy/build state — `deploys_and_rollbacks`, running status, last build label — for arbitrary stacks in the same Shipit instance, including ones the token holder has no legitimate access to. This matches the "unauthorized read of stack state" class of impact, since it grants read access across stack boundaries that the token's scope was designed to prevent.

### Likelihood Explanation
Any authenticated Shipit user with access to at least one stack can self-service a `read:stack` CCMenu token via `CCMenuUrlController#fetch`, and `stack_id` values are predictable (`owner/repo/environment`, visible throughout the UI/URLs). No special privilege, secret knowledge, or additional credential is required beyond a token that is trivially obtainable and normally considered low-sensitivity.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` relation (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that `ApiClient#stack_id` scoping is enforced identically to every other API controller.

### Proof of Concept
1. As an authenticated Shipit user with access to `stack_low_sensitivity`, visit `GET /ccmenu/owner/repo-a/staging` (routed to `Shipit::CCMenuUrlController#fetch`) to obtain a `read:stack` `ApiClient` token scoped to `stack_low_sensitivity` (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`).
2. Call the API endpoint directly with that token but a different stack's path: `GET /api/stacks/owner/repo-b/production/ccmenu?token=<token>`.
3. Because `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` (bypassing `current_api_client.stack_id` scoping), the request succeeds and returns `repo-b/production`'s deploy status, even though the token was only ever authorized for `repo-a/staging`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-10)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
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
