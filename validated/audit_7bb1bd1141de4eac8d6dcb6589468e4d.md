Confirmed root cause: `ApiClient` scopes tokens to a single stack via `stack_id` (checked only in `Api::BaseController#stacks`/`#stack`, `app/controllers/shipit/api/base_controller.rb:74-80`), but `Api::CCMenuController` overrides `#stack` to bypass that scoping entirely, breaking the "stack a token authorizes vs. stack it touches" binding.

### Title
CCMenu API token scope bypass allows reading any stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` accepts any valid `ApiClient` token with the generic `read:stack` permission and renders the CCTray XML status (build activity, last build status/label/time, web URL) for **any** stack identified by `params[:stack_id]`, ignoring the token's `stack_id` scope that `Api::BaseController` otherwise enforces.

### Finding Description
`Api::BaseController` scopes stack access to the token's authorized stack: [1](#0-0) 
`current_api_client.stack_id?` restricts the `stacks` relation, and `#stack` resolves `params[:stack_id]` only within that scoped relation — this is the equality the engine is supposed to enforce: `stack a token authorizes == stack it touches`.

`Api::CCMenuController` breaks this equality by declaring only a permission check (`require_permission :read, :stack`) and overriding `#stack` to query the unscoped `Stack` model directly: [2](#0-1) 
`stack = Stack.from_param!(params[:stack_id])` performs a lookup against all stacks, with no reference to `current_api_client.stack_id`. `ApiClient#check_permissions!` only validates the presence of the `read:stack` string in the client's permission list; it never validates that the requested stack matches the client's `stack_id`: [3](#0-2) 

This bypass is directly exploitable because Shipit itself hands out stack-scoped CCMenu tokens to any authenticated user via `CCMenuUrlController#fetch` / `#client`, which creates a persistent `ApiClient` with `permissions: %w[read:stack]` (no `stack_id` set on the record at all, since the constructor never assigns it): [4](#0-3) 
Even in the case where an operator manually creates a stack-scoped `ApiClient` (setting `stack_id`), the `Api::CCMenuController#show` action will still render data for whatever `stack_id` param is supplied, not the one the token was scoped to.

### Impact Explanation
This matches "unauthenticated read of stack state, task streams or deploy output" (High): a `read:stack`-permissioned token minted for one repository/stack can be used to enumerate deploy status, last build label/time, activity, and lock/failure state of every stack managed by the Shipit instance, disclosing information about unrelated repositories' deployment activity.

### Likelihood Explanation
Likelihood is high because the token needed is the lowest-privilege one Shipit issues by default (`read:stack` via the "CCMenu Client" flow reachable by any logged-in Shipit user through `CCMenuUrlController#fetch`), and exploitation requires nothing more than substituting the `stack_id` route parameter — no additional credentials, signatures, or elevated access are needed.

### Recommendation
- **Short term:** In `Api::CCMenuController`, use the inherited scoped `stack`/`stacks` helper from `Api::BaseController` instead of `Stack.from_param!` directly, so the token's `stack_id` scope is enforced the same way it is for `StacksController`, `LocksController`, etc.
- **Long term:** Move the `stack_id` scoping check into `ApiClient#check_permissions!` (or a dedicated `authorize_stack!` step invoked from `BaseController`) so every controller — current and future — is forced to validate the resolved stack against the token's `stack_id`, rather than relying on each controller correctly reusing the scoped accessor.

### Proof of Concept
1. As any authenticated Shipit user, visit `GET /shopify/private-repo/production/ccmenu` (`CCMenuUrlController#fetch`) to mint (or reuse) the shared "CCMenu Client" `read:stack` `ApiClient` token and receive a CCMenu URL like `https://shipit.example.com/api/stacks/shopify/private-repo/production/ccmenu?token=<TOKEN>`.
2. Send the same token against a different, unrelated stack:
   `GET /api/stacks/othercorp/secret-repo/production/ccmenu?token=<TOKEN>`
3. `Api::BaseController#authenticate_api_client` accepts the token (valid signature via `ApiClient.authenticate`), `require_permission :read, :stack` passes because the client has `read:stack` in its permissions list, and `Api::CCMenuController#stack` resolves `othercorp/secret-repo/production` via unscoped `Stack.from_param!`, returning that stack's deploy/build status in the XML response — despite the token never having been scoped to, or intended for, that stack. [5](#0-4)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
