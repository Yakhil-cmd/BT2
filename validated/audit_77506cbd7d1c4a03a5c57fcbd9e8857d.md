### Title
API-scoped token bypasses its stack-authorization boundary in CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
### Finding Description
The report's bug class is a mismatch between what a credential is *verified* to authorize and what it is actually *used* to act on (there, ETH-price authorization vs. USD-denominated action). The analogous binding in this engine is: **the stack a token authorizes == the stack it touches**.

`Shipit::Api::BaseController` establishes this binding correctly for every other stack-scoped API endpoint: `stacks` is restricted to the token's `stack_id` when the `ApiClient` is stack-scoped, and `stack` is derived from that restricted relation: [1](#0-0) 

`Api::CCMenuController`, however, overrides `stack` to resolve directly from the global `Stack` relation, completely bypassing the `stacks` scoping method that enforces the token's `stack_id` restriction: [2](#0-1) 

`require_permission :read, :stack` only checks that the token has the `read:stack` *permission string* — it never checks that the requested `stack_id` matches the token's bound `stack_id`: [3](#0-2) [4](#0-3) 

So the equality the system is supposed to enforce — `token.stack_id == requested_stack_id` (when `stack_id` is set) — never holds for this controller; only `token.permissions.include?("read:stack")` is checked, while the stack actually touched is whatever `stack_id` appears in the URL.

### Impact Explanation
This is a High-severity issue per the listed categories: "unauthenticated/under-authorized read of stack state". A token that is deliberately scoped to a single stack (e.g., the CCMenu tokens minted by `CCMenuUrlController#client`, which are created with only `read:stack` permission and handed out per-stack, or any similarly-scoped `ApiClient`) can be replayed against `GET /api/stacks/*stack_id/ccmenu` for **any other stack in the installation**, not just the one it was authorized for. The response leaks stack existence, name, activity, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and lock state for stacks the token holder has no authorization to see — an authorization scope violation that the rest of the API surface (stacks, tasks, deploys, hooks, etc., which all use the inherited `stack`/`stacks` methods) correctly prevents.

### Likelihood Explanation
High likelihood: this requires no privileged access beyond possessing any valid, even minimally-scoped, API/CCMenu token (which is explicitly designed to be shared/embedded in CI dashboards per `CCMenuUrlController`), and only a trivial URL parameter change (`stack_id`) to pivot from the authorized stack to an arbitrary target stack. `Api::CCMenuController` is the only stack-scoped controller in the API namespace that overrides `stack` this way; every sibling controller (`StacksController`, `TasksController`, `DeploysController`, `RollbacksController`, etc.) correctly inherits the scoped `stack`/`stacks` methods.

### Recommendation
Remove the `stack` override in `app/controllers/shipit/api/ccmenu_controller.rb` and use the inherited `BaseController#stack` (which resolves through the scoped `stacks` relation), so a stack-restricted `ApiClient` can only reach the stack it was authorized for.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (this is exactly what `CCMenuUrlController#client` does for each stack's "CCMenu URL").
2. As an attacker who obtains/observes that token (e.g., a shared build-monitor URL), issue:
   `GET /api/stacks/*B/ccmenu` (arbitrary other repo/branch/environment `B`) with `Authorization: Basic <token>--`.
3. `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` succeeds (token has `read:stack`), and `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` against stack `B` directly — ignoring that the token's `stack_id` is `A`.
4. The controller renders `B`'s CCMenu XML (build status, last build label/time, lock state), which the token was never authorized to view.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
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
