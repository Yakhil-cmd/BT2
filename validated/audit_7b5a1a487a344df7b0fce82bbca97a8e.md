### Title
Stack-scoped API token can read the CI status of any stack, not just the stack it was issued for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` implements per-token stack scoping so that a token created with a `stack_id` can only see that one stack, but `Api::CCMenuController` overrides the `stack` accessor with a version that looks up the requested `stack_id` param against the entire `Stack` table, completely bypassing that scoping check.

### Finding Description
`Api::BaseController` defines the scoping contract that every API endpoint is supposed to honor: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the token is scoped, and `stack` resolves `params[:stack_id]` only within that restricted set - this is exactly the "stack a token authorises" binding.

`Api::CCMenuController`, however, redefines `stack` to bypass `stacks` entirely and resolve `params[:stack_id]` against the unscoped `Stack` model: [2](#0-1) 

The controller only enforces a coarse `require_permission :read, :stack` check (a boolean membership test on the token's `permissions` array), never a check that the requested stack matches `current_api_client.stack_id`: [3](#0-2) 

So the equality that should hold - `current_api_client.stack_id == stack.id` (when the token is scoped) - is never evaluated for this controller. Any token with the `read:stack` permission, scoped or not, can pass an arbitrary `stack_id` and the controller happily resolves and renders it.

Such scoped tokens are trivially self-serviceable: `CCMenuUrlController#fetch`, reachable by any authenticated Shipit user, auto-creates (or reuses) a `read:stack`-only, stack-scoped `ApiClient` for the requesting user and hands back its token: [4](#0-3) 

### Impact Explanation
This breaks the "stack a token authorises versus a stack it touches" trust boundary. A user (or anything holding a stack-scoped CCMenu token) who is only meant to see one stack's CI/deploy status can enumerate `stack_id` and read the build/deploy state (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, lock status) of every stack in the Shipit instance, including stacks belonging to repositories/teams the token holder has no legitimate visibility into. This is an unauthorized cross-stack read of stack state, matching the "High - unauthenticated/unauthorized read of stack state" impact category, since the scoping mechanism was specifically intended to prevent exactly this.

### Likelihood Explanation
High. Exploitation requires no special privilege beyond being a normal authenticated Shipit user with access to at least one stack's CCMenu URL (a self-service, unprivileged flow). No collusion, no admin action, and no knowledge of secrets is required - only changing a URL parameter (`stack_id`) on a request that already carries a valid, legitimately-issued token.

### Recommendation
In `Api::CCMenuController`, remove the local `stack` override and use the inherited, scoping-aware `Api::BaseController#stack`/`#stacks` methods (or explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == resolved_stack.id` before rendering), so that stack-scoped tokens cannot resolve stacks outside their assigned `stack_id`.

### Proof of Concept
1. As a normal authenticated Shipit user, visit `/ccmenu/<stack_a>` (`CCMenuUrlController#fetch`) to obtain a `read:stack`-scoped `ApiClient` token for stack A: [5](#0-4) 
2. Use the returned `ccmenu_url` (which embeds the token) but replace the `stack_id` in the path/segment with stack B's identifier (any other stack in the instance).
3. Observe that `Api::CCMenuController#show` resolves `stack` via `Stack.from_param!(params[:stack_id])` - ignoring the token's `stack_id` scope - and returns stack B's CI/deploy XML, even though the token was only ever authorized for stack A: [6](#0-5)

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
