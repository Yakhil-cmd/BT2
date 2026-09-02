### Title
API-scoped `ApiClient` tokens bypass their `stack_id` restriction in the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces per-token stack scoping through the `stacks`/`stack` helper methods, but `Shipit::Api::CCMenuController` overrides `stack` with an unscoped lookup, letting a stack-scoped `ApiClient` token read build/deploy status for any stack in the installation.

### Finding Description
Shipit's API authorization model binds an `ApiClient` to (at most) one stack via `stack_id`. `BaseController` implements this binding as:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

Every controller that inherits `stack` from `BaseController` (e.g. `Api::StacksController`, deploys, tasks, hooks, lock, etc.) is therefore constrained to the stack(s) the token authorizes.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping and query the model directly:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`require_permission :read, :stack` only checks the operation/scope pair on the token's `permissions` list via `ApiClient#check_permissions!` — it never checks which specific stack the token is bound to: [3](#0-2) 

This is the same class of bug as the reported "collaterals_values" miscalculation: the code that is supposed to compute/enforce a bounded value (max LTV / authorized stack set) is replaced, in one code path, by an unconstrained equivalent that discards the accumulated restriction. Here the equality that should hold is:

`stack a token authorizes == stack the CCMenu endpoint touches`

but `CCMenuController#stack` breaks it by resolving directly against `Stack.from_param!` instead of the scoped `stacks.from_param!`.

### Impact Explanation
An `ApiClient` created with `stack_id` set (the mechanism administrators use to hand out a token restricted to a single stack, e.g. via `CCMenuUrlController#client`, which explicitly creates a `read:stack`-only, stack-scoped client) can be used to read CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, deploy output URL) for *any* stack in the Shipit instance, not just the one it was issued for. This is an authorization-boundary break: escalation beyond the token's authorized scope to unauthenticated (from the target stack's perspective) read of stack state/deploy status, matching the "High" impact criterion for unauthorized read of stack state / deploy output via a scope token that should have been confined to one stack.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token (e.g. the `CCMenu Client` created by `CCMenuUrlController`, a common integration point for exposing a single stack's CI status widget) can trivially exploit this by simply changing the `stack_id` segment of the CCMenu URL to another stack's identifier — no additional privilege, secret, or race condition is required. This makes the likelihood high for anyone who already has one narrowly-scoped token, which is the exact population this scoping feature is meant to restrict.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup inherited from `BaseController` instead of querying `Stack` directly, i.e. remove the override or implement it as `stacks.from_param!(params[:stack_id])`, mirroring how `Api::StacksController#stack` uses `stacks.from_param!(params[:id])`.

### Proof of Concept
1. Admin creates a stack-scoped CCMenu token for `Stack A` (as `CCMenuUrlController#client` does): `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator:, name: 'CCMenu Client')`, with `stack_id` set to Stack A's id.
2. Using that token's `authentication_token`, call:
   `GET /api/stacks/<owner>/<name-of-stack-B>/ccmenu?token=<TOKEN>`
3. Because `CCMenuController#stack` resolves via `Stack.from_param!(params[:stack_id])` (unscoped) rather than `stacks.from_param!` (scoped to `current_api_client.stack_id`), the request succeeds and returns Stack B's build/deploy status even though the token is only authorized for Stack A. [4](#0-3) [5](#0-4)

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
