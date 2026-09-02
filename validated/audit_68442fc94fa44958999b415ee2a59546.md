### Title
API Client Stack Scoping Bypass in `CCMenuController#stack` Grants Unauthorized Read of Any Stack's Deploy State - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` authenticates callers with a raw `ApiClient` token and only checks the generic `read:stack` permission, but then resolves the target stack with the unscoped `Stack.from_param!(params[:stack_id])` instead of the tenant-scoped `stacks.from_param!(params[:stack_id])` helper used everywhere else in the API. This breaks the binding "stack a token authorizes == stack it touches," letting a client token that is scoped to one stack read the deploy/rollback status of any stack in the installation.

### Finding Description
`BaseController` establishes the authorization invariant for scoped `ApiClient`s: when an `ApiClient` has a `stack_id` set, the set of stacks it may touch is restricted to that one stack via `stacks`, and `stack` is derived from that restricted relation: [1](#0-0) 

`require_permission` only checks a coarse operation/scope pair (e.g. `read:stack`), not which specific stack is authorized: [2](#0-1) [3](#0-2) 

All other API controllers (`stacks_controller.rb`, etc.) rely on `BaseController#stack`, which goes through the scoped `stacks` relation, so a client bound to one stack cannot resolve another stack's ID. `CCMenuController`, however, overrides both authentication and stack resolution: [4](#0-3) 

Its `authenticate_api_client` accepts a token from a URL query parameter (`params[:token]`) rather than HTTP Basic Auth, and its `stack` method calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model — completely bypassing the `stacks` (tenant-scoped) relation that `BaseController` defines for this exact purpose. The `require_permission :read, :stack` before_action only confirms the presented token carries the `read:stack` permission string; it performs no per-stack ownership check, and the overridden `stack` method never consults `current_api_client.stack_id`.

### Impact Explanation
An `ApiClient` record legitimately scoped to a single stack (`ApiClient#stack_id` set, as exercised by the "an api client scoped to a stack will only see that one stack" test path in `stacks_controller_test.rb`) is expected to be confined to that stack across the whole API surface. Via `CCMenuController#show`, that same token can instead be replayed with an arbitrary `stack_id` in the URL to read the latest deploy/rollback status (`id`, `ended_at`, `running?`) of any stack in the Shipit instance, including stacks belonging to other repositories/teams the token holder was never granted access to. This is an unauthenticated-relative-to-scope read of stack/task state, matching the "High — unauthenticated read of stack state, task streams or deploy output" impact class, since it escalates a narrowly-scoped credential into installation-wide read access.

### Likelihood Explanation
Any holder of a valid `ApiClient` token with `read:stack` permission (including tokens intentionally minted for a single stack, e.g. the CCMenu-specific client created in `CCMenuUrlController#client`) can trigger this by simply changing the `stack_id` path/query parameter — no additional privilege, secret, or session is required beyond the token itself, which is the exact credential this endpoint is designed to accept. This requires no cooperation from a maintainer and no write access; it is a single unauthenticated (relative to scope) GET request.

### Recommendation
In `CCMenuController`, resolve the stack through the tenant-scoped relation instead of the bare `Stack` model, mirroring `BaseController#stack`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures a stack-scoped `ApiClient` (`current_api_client.stack_id?`) can only resolve its own stack, consistent with every other API controller.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A (e.g., via `CCMenuUrlController`, which mints exactly such a client for the current user).
2. Retrieve that client's `authentication_token`.
3. Call `GET /stacks/:stack_id/ccmenu.xml?token=<token>` where `:stack_id` is set to Stack B (a different, unrelated stack) instead of Stack A.
4. `authenticate_api_client` in `CCMenuController` succeeds since the token is valid.
5. `require_permission :read, :stack` passes because the client has the `read:stack` permission string, irrespective of which stack.
6. `stack` resolves via `Stack.from_param!(params[:stack_id])` to Stack B (bypassing the intended single-stack scope), and the response discloses Stack B's latest deploy/rollback status — data the token was never authorized to access.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-21)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
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
