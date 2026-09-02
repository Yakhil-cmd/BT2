### Title
CCMenu API bypasses ApiClient stack scoping, allowing a stack-restricted token to read any stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via the `stack_id` column, and every other API controller enforces that scope by resolving the target stack through the `stacks` helper (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`). `Shipit::Api::CCMenuController` breaks this binding: it resolves the requested stack directly with `Stack.from_param!(params[:stack_id])`, never routing through the scoped `stacks` relation, so a token authorized for stack A can be used to read CCMenu build-status data for any stack B.

### Finding Description
`Shipit::Api::BaseController#stacks` is the canonical scoping mechanism: [1](#0-0) 

Controllers such as `Shipit::Api::StacksController` correctly resolve the target stack through this scoped relation: [2](#0-1) 

`Shipit::Api::CCMenuController`, however, only checks the coarse `read:stack` permission bit and then resolves the stack directly from the unscoped `Stack` model, ignoring `current_api_client.stack_id` entirely: [3](#0-2) 

`ApiClient#check_permissions!` only validates that the permission string (e.g. `read:stack`) is present in the client's `permissions` array — it has no notion of *which* stack is being accessed: [4](#0-3) 

The binding that should hold is: **stack(s) a token authorizes == stack(s) a token can touch**, i.e. `current_api_client.stack_id? ? current_api_client.stack_id : any` should equal the `stack_id` used to fetch data. In `CCMenuController#stack`, the left side (`current_api_client.stack_id`) is never consulted, while the right side (`params[:stack_id]`) is attacker-controlled, breaking the equality.

This scoped-token pattern is exactly what `CCMenuUrlController` sets up: it mints an `ApiClient` restricted to `permissions: %w[read:stack]` for one specific stack, intended to be embedded in a CI-radiator/CCMenu URL: [5](#0-4) 

That token is meant to disclose build status for one stack only, but because `CCMenuController#stack` does not use the scoped `stacks` relation, the same token/URL parameter can be repointed at any `stack_id` on the Shipit instance.

### Impact Explanation
Any holder of a stack-scoped CCMenu token (these URLs are commonly shared with build-radiator/monitoring tools, which is a lower-trust, semi-public distribution context by design) can enumerate and read the deploy state — `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl` — of every stack in the Shipit instance, not just the one stack the token creator intended to expose. This is an unauthorized read of stack/deploy state outside the token's granted authorization scope, matching the "unauthenticated/unauthorized read of stack state ... deploy output" class of impact, since the check that should gate this by stack identity is absent.

### Likelihood Explanation
Exploitation requires only possession of a single valid CCMenu token that was intentionally scoped to one stack (an unprivileged credential distributed via `CCMenuUrlController#fetch`), and the request path (`GET /api/stacks/:stack_id/ccmenu.xml?token=...`) is a standard, always-reachable engine endpoint. No repository write access, session, or privileged account is needed — only the low-privilege, stack-scoped token itself, which by design is meant to only ever see one stack.

### Recommendation
In `Shipit::Api::CCMenuController`, resolve the stack through the same scoped relation used elsewhere (`stacks.from_param!(params[:stack_id])`) instead of the bare `Stack.from_param!`, so a stack-scoped `ApiClient` cannot be used to fetch data for stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. As an authorized Shipit user, request a CCMenu URL for stack A via `CCMenuUrlController#fetch`, which creates/returns an `ApiClient` with `permissions: %w[read:stack]` and `stack_id` fixed to stack A, embedding `token=<A's authentication_token>` in the returned URL.
2. Take that token and issue `GET /api/stacks/<stack_B_id_or_param>/ccmenu.xml?token=<A's token>` for any other stack B on the instance.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the token has the `read:stack` bit, and `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` — resolving stack B despite the token being scoped to stack A only.
4. The response discloses stack B's `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl`, even though the token was never authorized for stack B.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-36)
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
