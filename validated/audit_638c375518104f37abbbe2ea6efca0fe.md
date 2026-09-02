Found it: `CCMenuController#stack` bypasses the stack-scoping used everywhere else in the API.

### Title
CCMenu endpoint permits a stack-scoped API token to read state of any stack, not just the stack it authorizes - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces a binding: `stack_id` authorized by the token == `stack` touched by the request, implemented via the `stacks` helper that filters by `current_api_client.stack_id` before resolving `params[:stack_id]`. `CCMenuController` overrides `stack` to bypass this scoping helper entirely, breaking that equality.

### Finding Description
Every other API controller (e.g. `StacksController#stack` at `app/controllers/shipit/api/stacks_controller.rb:87-89`) resolves the target stack via `stacks.from_param!(...)`, where `stacks` is defined in `app/controllers/shipit/api/base_controller.rb:74-76`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```

This enforces the binding: `authorized_stack(token) == touched_stack(request)` for tokens created with `stack_id` set (e.g. the `here_come_the_walrus` fixture, or any client created via `CCMenuUrlController#client` at `app/controllers/shipit/ccmenu_url_controller.rb:15-18`, which scopes the client to `permissions: %w[read:stack]` and a single stack).

`CCMenuController`, however, defines its own `stack` method that ignores `stacks` and resolves directly against the global table: [1](#0-0) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

`require_permission :read, :stack` at line 6 only checks that the token has the `read:stack` permission string; it never checks which stack the token is scoped to (`ApiClient#check_permissions!` at `app/models/shipit/api_client.rb:38-45` only compares against `PERMISSIONS`, it has no stack-identity check). Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, a token whose `stack_id` is set to Stack A can be used with any `stack_id` path parameter to read the CI-status XML (`#show`, `app/controllers/shipit/api/ccmenu_controller.rb:22-25`) — including `lastBuildStatus`, deploy activity, and lock status — of Stack B, C, etc.

### Impact Explanation
This is an unauthenticated-read escalation matching the "High" bucket ("unauthenticated read of stack state ... task streams or deploy output") — the token only proves possession of a `read:stack`-scoped credential for one specific stack (as issued for the CCMenu integration, e.g. via `CCMenuUrlController`), yet it can be replayed against `stack_id` values it was never authorized for, disclosing deploy/build status for stacks outside its granted scope.

### Likelihood Explanation
High likelihood: the CCMenu URL/token is generated and embedded in a CI-status widget URL (`CCMenuUrlController#fetch`, `app/controllers/shipit/ccmenu_url_controller.rb:7-11`) that is often shared/exposed relatively openly (dashboards, browser extensions). Any holder of one such token/URL can simply change the `stack_id` in the URL to enumerate other stacks' status without any additional secret.

### Recommendation
Change `CCMenuController#stack` to use the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that a stack-scoped token cannot be used to read stacks outside its `stack_id` binding.

### Proof of Concept
1. Via `CCMenuUrlController#fetch` (or directly in `ApiClient`), obtain/create an `ApiClient` scoped to Stack A: `ApiClient.create!(permissions: %w[read:stack], stack_id: stack_a.id, creator: user, name: 'x')`.
2. Compute its `authentication_token`.
3. Send `GET /api/stacks/<stack_b_id>/ccmenu.xml?token=<token>` where `stack_b` is a different, unauthorized stack.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing the `stacks` scoping in `BaseController`), the request succeeds and renders Stack B's build/deploy status, even though the token was only ever authorized for Stack A. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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
