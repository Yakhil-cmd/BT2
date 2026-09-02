I found a clear binding break: the CCMenu API endpoint bypasses the stack-scoping restriction that `Api::BaseController` otherwise enforces on tokens.

## Analysis

`Api::BaseController` defines the token-to-stack binding used by every other Api controller: [1](#0-0) 

`current_api_client.stack_id?` scopes the client's visible stacks to just the one it was created for, and `stack` resolves `params[:stack_id]` only within that scope — this is the "stack a token authorises" binding.

`Api::CCMenuController`, however, overrides `stack` with an unscoped lookup and also allows token authentication via a query-string parameter: [2](#0-1) 

Because `stack` is redefined to call `Stack.from_param!(params[:stack_id])` directly (line 29-31) instead of `stacks.from_param!(...)`, the `stack_id`-scoping performed by `ApiClient#stack_id?` in the base controller is never applied here. `require_permission :read, :stack` only checks `ApiClient#check_permissions!`, which just checks the `permissions` array — it does not check `stack_id` at all: [3](#0-2) 

So an `ApiClient` created and scoped to one stack (e.g., the `here_come_the_walrus` fixture, scoped to `shipit`) still holds `read:stack` permission, and that permission check passes for *any* stack requested via `stack_id`, letting the client's token read CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock status, etc.) for stacks it was never authorized for — breaking the equality `stack a token authorises == stack it touches`.

### Title
Stack-scoped API tokens can read CCMenu build status of unauthorized stacks - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` overrides the base controller's stack-scoping logic with an unscoped `Stack.from_param!(params[:stack_id])` lookup, so an `ApiClient` token that is bound to a single stack (`stack_id` column) can nonetheless request `/api/:stack_id/cc.xml` for any other stack in the installation and receive its CI/deploy status, as long as its permission list includes `read:stack`.

### Finding Description
`Api::BaseController#stack` (app/controllers/shipit/api/base_controller.rb:74-80) is the canonical way controllers resolve the target stack; it filters through `stacks`, which itself is restricted to `Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true. This is the mechanism by which a stack-scoped `ApiClient` is prevented from acting on stacks outside its scope.

`Api::CCMenuController` redefines `stack` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) to bypass `stacks` entirely and call `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, which performs no client-scoping (app/models/shipit/stack.rb:515-525). `ApiClient#check_permissions!` (app/models/shipit/api_client.rb:38-45) also never inspects `stack_id`; it only checks the `permissions` string array. Consequently, `require_permission :read, :stack` on this controller enforces that the token *has* `read:stack` in its permission list, but never verifies the requested stack matches the token's bound `stack_id`.

### Impact Explanation
This allows unauthenticated-relative-to-stack read of stack state: any valid API token carrying `read:stack` — even one deliberately scoped to a single stack for least-privilege reasons — can enumerate and read the CI/deploy status of every other stack managed by the Shipit instance via the CCMenu endpoint. This matches the "High" impact category of unauthorized read of stack state.

### Likelihood Explanation
Any holder of a stack-scoped API token (the exact use case that `stack_id` scoping on `ApiClient` exists to restrict) can trigger this with a single unauthenticated-by-stack GET request; no additional privilege or race condition is required.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped `stacks` collection from the base controller (i.e. `@stack ||= stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `stack_id` binding enforced elsewhere in `Api::BaseController` is also honored here.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (as in fixture `here_come_the_walrus`).
2. Authenticate as that client and issue `GET /api/<owner>/<repo-B>/<environment-B>/cc.xml?token=<token>` where stack B is a *different* stack than A.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unscoped, the request succeeds and returns stack B's build status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state), despite the token being provisioned only for stack A. [4](#0-3) [1](#0-0) [3](#0-2)

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
