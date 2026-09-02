### Title
`Api::CCMenuController#stack` bypasses ApiClient stack scoping, letting a stack-scoped token read any other stack's build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::StacksController` (and `Api::BaseController` in general) enforce a binding between an `ApiClient`'s `stack_id` (the stack it is authorized for) and the stack a request actually touches, by resolving stacks through the `stacks` scope. `Api::CCMenuController` overrides `#stack` to bypass that scope entirely and resolve `params[:stack_id]` against the full `Stack` table, breaking the `token.stack_id == stack.id` binding.

### Finding Description
`Api::BaseController` defines the intended trust binding: an `ApiClient` scoped to a stack may only ever resolve stacks from that scope. [1](#0-0) 

`Api::StacksController` correctly inherits this behavior and resolves via the scoped `stacks` relation: [2](#0-1) 

`Api::CCMenuController`, however, overrides `#stack` to resolve directly against `Stack.from_param!(params[:stack_id])`, completely bypassing the `current_api_client.stack_id?` scoping that `BaseController#stacks` enforces: [3](#0-2) 

The only authorization gate left on this controller is the coarse-grained permission check `require_permission :read, :stack`, which merely checks that the `ApiClient#permissions` array contains `"read:stack"` — it does not check which specific stack the client is scoped to: [4](#0-3) 

So the equality that should hold — "the stack a token authorizes access to" == "the stack the request touches" — is broken specifically in this controller. Every other stack-facing endpoint (`Api::StacksController`, `Api::TasksController`, etc.) preserves it via `stacks.from_param!`, but `CCMenuController` does not.

### Impact Explanation
An `ApiClient` created and scoped to one specific stack (a common configuration pattern, exactly as exercised by `here_come_the_walrus` in the test fixtures, which is scoped to the `shipit` stack with only `read:stack` permission) can use its token to call `GET /api/stacks/:stack_id/ccmenu.xml` with an **arbitrary** `stack_id` belonging to any other stack in the installation, and get back that other stack's CCTray project status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock status, etc.): [5](#0-4) 

This is an unauthenticated (relative to that other stack) disclosure of deploy/task state for a stack the token was never authorized to touch — matching the "High: escalation into ... unauthenticated read of stack state, task streams or deploy output" impact bucket, without requiring anything beyond a legitimately-issued, narrowly-scoped `ApiClient` token (which is the intended, low-privilege credential for this exact scenario).

### Likelihood Explanation
High likelihood in any deployment that issues stack-scoped `ApiClient` tokens (a documented, supported feature exposed via the `ApiClientsController` UI and the `CCMenuUrlController` helper, which builds CCMenu URLs from such tokens). No special access is needed beyond possessing one such token — an attacker only needs to know or guess another stack's `owner/name/environment` param to query it. `stack.to_param` values are frequently visible in the UI/URLs, making the target predictable.

### Recommendation
Remove `Api::CCMenuController`'s custom `#stack` override, or reimplement it to resolve through the inherited, scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) exactly like `Api::StacksController` does, so the ApiClient's `stack_id` scoping is honored consistently across all API endpoints.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to Stack A (`stack_id` = A.id) with permission `read:stack` (equivalent to fixture `here_come_the_walrus`).
2. Authenticate to `GET /api/stacks/:owner/:name/:env/ccmenu.xml` using that token, but substitute `params[:stack_id]` with Stack B's param (a stack the client was never scoped to).
3. `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `current_api_client.stack_id` scoping used elsewhere), returning Stack B.
4. `require_permission :read, :stack` only checks the permission string, not the stack scope, so the request succeeds and Stack B's CCMenu/build status is returned to a token that was only supposed to see Stack A. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
