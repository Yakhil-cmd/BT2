### Title
Cross-stack authorization bypass in `Api::CCMenuController#stack` breaks the "stack a token authorises" vs "stack a token touches" binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` scopes an `ApiClient`'s visible stacks to `current_api_client.stack_id` when the client is stack-restricted, via `stacks`/`stack` helpers. `Api::CCMenuController` overrides `stack` with an unscoped `Stack.from_param!(params[:stack_id])`, so a stack-scoped API token can read CCTray/CCMenu deploy status for any stack, not just the one it was authorized for.

### Finding Description
`BaseController#stacks` restricts the queryable set of stacks to the ones an `ApiClient` is authorized for: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `BaseController#stack` builds on that scoped relation via `stacks.from_param!(params[:stack_id])`. [1](#0-0) 

`Api::CCMenuController` requires only the generic `read:stack` permission and defines its own `stack` method that queries `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, bypassing the `stack_id` scoping entirely: [2](#0-1) 

`ApiClient#check_permissions!` only verifies the presence of the coarse-grained permission string (`"read:stack"`) in the client's `permissions` array; it has no notion of which specific `stack_id` the operation targets. [3](#0-2) 

This breaks the intended binding: **stack a token authorises == stack a token touches**. An `ApiClient` created with `stack_id` set to Stack A (e.g., via the "CCMenu Client" auto-provisioning flow in `CcmenuUrlController`, which creates a client scoped `permissions: %w[read:stack]` bound to one stack) is meant to only ever see Stack A. But because `CCMenuController#stack` ignores that scoping, the same token can be used with `params[:stack_id]` set to any other stack's identifier and will successfully render that other stack's deploy/task state. [4](#0-3) 

### Impact Explanation
This is a cross-stack authorization bypass: a token minted for one stack can read the deploy/task state (`deploys_and_rollbacks`, running status, timestamps) of every other stack in the installation. This matches the "unauthenticated read of stack state" class of impact called out in scope (here more precisely "unauthorized read of another stack's state using a token not authorized for that stack"), since the intended per-stack authorization boundary enforced elsewhere in the API (`BaseController#stack`) is not applied in this controller.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped API token (e.g., from the CCMenu URL feature, or any `ApiClient` created with a `stack_id` and `read:stack` permission) can exploit this without further privilege — they only need to change the `stack_id` request parameter to target a different stack. No secret material, GitHub credentials, or session is required beyond the token they already legitimately hold for their own stack.

### Recommendation
Have `Api::CCMenuController#stack` reuse the scoped `stacks` relation from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so stack-restricted `ApiClient`s cannot access stacks outside their authorized `stack_id`.

### Proof of Concept
1. Provision (or have provisioned) a stack-scoped `ApiClient` for Stack A, e.g. via `CcmenuUrlController#fetch`, which creates a client with `permissions: %w[read:stack]` and `stack: <Stack A>`. [4](#0-3) 
2. Using that token's Basic-Auth credentials, call `GET /api/stacks/:stack_id/ccmenu.xml` where `:stack_id` is Stack B's identifier (a stack the token was never authorized for). [5](#0-4) 
3. `authenticate_api_client` succeeds (valid token) and `require_permission :read, :stack` succeeds (the client does have the generic `read:stack` permission), then `stack` resolves Stack B directly via `Stack.from_param!`, bypassing the `stack_id` restriction that `BaseController#stacks` would have otherwise enforced.
4. The response renders Stack B's latest deploy/rollback state, disclosing state the token was never authorized to view.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
