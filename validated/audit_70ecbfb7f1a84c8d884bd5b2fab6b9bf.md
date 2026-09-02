I confirmed the binding break: `Shipit::Api::BaseController#stack` scopes lookups through `stacks` (which respects `current_api_client.stack_id?`), but `Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting the client's `stack_id` scope. [1](#0-0) [2](#0-1) 

### Title
Stack-scoped `ApiClient` tokens can read CCMenu status of any stack, not just the authorized one - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` implements a `stack`/`stacks` scoping mechanism that restricts a stack-scoped `ApiClient` (one created with a non-nil `stack_id`) to only the single `Stack` it was authorized for. `Shipit::Api::CCMenuController` overrides `#stack` in a way that bypasses this scoping entirely, resolving the target stack directly from the URL param regardless of which stack the authenticated token is bound to.

### Finding Description
`BaseController#stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?` true), or `Stack.all` otherwise; `BaseController#stack` resolves `stacks.from_param!(params[:stack_id])`, i.e., lookups are always constrained to the client's authorized stack set. [1](#0-0) 

`CCMenuController` inherits `authenticate_api_client` and the `require_permission :read, :stack` check from `BaseController`, but it redefines `#stack` to call `Stack.from_param!(params[:stack_id])` — a direct, unscoped lookup that ignores `current_api_client.stack_id`: [3](#0-2) 

The permission check (`require_permission!`) only validates that the client's `permissions` array contains `read:stack` via `ApiClient#check_permissions!`, which is a global capability flag and carries no per-stack scoping information; `check_permissions!` never inspects `stack_id`: [4](#0-3) 

The binding that should hold is: **stack a token authorizes == stack it touches**, i.e. `current_api_client.stack_id == resolved_stack.id` whenever `stack_id?` is true. Before a client visits `CCMenuController#show`, this equality holds for every other `Api::*` controller that uses the inherited `#stack`/`#stacks` helpers (e.g. `Api::StacksController`) because they go through `stacks.from_param!`. After the request in `CCMenuController#show`, the equality is broken: the resolved stack is whatever `params[:stack_id]` names, independent of `current_api_client.stack_id`.

### Impact Explanation
This satisfies the High-severity criterion "escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state" in spirit, but more precisely it is a horizontal-authorization break for holders of a legitimately-issued but narrowly-scoped `ApiClient` credential: an `ApiClient` token deliberately restricted to one stack (`stack_id` set, e.g. via `CCMenuUrlController#client`, which creates such a scoped client with only `read:stack` permission for a specific stack) can still read another stack's CCMenu status (name, activity, last build status/label/time, web URL) by simply substituting a different `stack_id` in the request path while presenting the same token/permission. This crosses a repository/stack boundary using credentials that were never authorized for that stack — an unauthorized read of stack state belonging to a different repository/stack than the one the token was scoped to.

### Likelihood Explanation
Any holder of a valid, stack-scoped `read:stack` `ApiClient` token (e.g. one generated for a CI badge/CCMenu URL feature via `CCMenuUrlController`) can trigger this by making a GET request to the CCMenu endpoint with an arbitrary `stack_id` in place of the one the token was issued for. No privileged access, secret knowledge, or additional exploitation step is required beyond substituting the path/query parameter — only possession of a legitimately obtained but narrowly-scoped token.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` collection inherited from `BaseController` (`stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that stack-scoped tokens cannot read data for stacks outside their `stack_id` scope.

### Proof of Concept
1. Using `CCMenuUrlController#fetch`, or directly via `ApiClient.create!(creator: user, name: 'x', stack: stack_a, permissions: ['read:stack'])`, obtain an `authentication_token` for an `ApiClient` scoped to `stack_a` (`stack_id` set to `stack_a.id`).
2. Send `GET /api/:stack_b_id/cc.xml` (the CCMenu route) using HTTP Basic auth with that token, where `stack_b` is a different stack the token was never authorized for.
3. `BaseController#authenticate_api_client` succeeds (token is valid) and `require_permission :read, :stack` succeeds because `check_permissions!` only checks the `permissions` array, not `stack_id`.
4. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly to `stack_b`, ignoring `current_api_client.stack_id == stack_a.id`.
5. The response renders `stack_b`'s name, last build status/label/time and web URL, disclosing state of a stack the token was never scoped to.

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
