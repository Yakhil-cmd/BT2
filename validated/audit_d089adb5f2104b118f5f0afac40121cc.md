### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` resolves the target stack directly from the request parameter instead of going through the scoped lookup used everywhere else in the API, breaking the binding between the stack an `ApiClient` token is authorized for and the stack the controller actually acts on.

### Finding Description
Every other API controller inherits `stack` from `Api::BaseController`, which restricts lookups to the client's authorized stack: [1](#0-0) 

`stacks` is filtered to `current_api_client.stack_id` when the token is scoped to a stack, otherwise all stacks are visible. This is the mechanism that makes a stack-scoped `ApiClient` (`stack_id` set, e.g. fixture `here_come_the_walrus` with only `read:stack`) safe to hand out: the *permission* check (`read:stack`) only verifies the operation, and the *scope* check (`stacks.from_param!`) is what confines it to a single stack.

`Api::CCMenuController` overrides both `authenticate_api_client` (to accept a token via query param) and `stack`, but the overridden `stack` method calls `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `current_api_client.stack_id` scoping: [2](#0-1) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks the client's `permissions` array for `"read:stack"` and never inspects `stack_id`: [3](#0-2) 

So the binding that should hold is:
`stack the ApiClient token authorizes == stack the controller action touches`

Before the request: a token scoped to Stack A (`stack_id = A`, permission `read:stack`) is only supposed to be usable to read Stack A.
After a crafted request to `CCMenuController#show` with `stack_id=B` in the path and the Stack-A token as the `token` param: the permission check passes (the token does have `read:stack`), and `stack` resolves to Stack B unconditionally, so the response returns Stack B's latest deploy/rollback status.

### Impact Explanation
This lets any holder of a stack-scoped, read-only API token (which is explicitly meant to be narrowly scoped, e.g. tokens minted by `CCMenuUrlController` for embedding in third-party CI dashboards) read deploy/rollback state (`running?`, `ended_at`, deploy id) for every other stack in the Shipit instance, including stacks/repositories the token holder has no legitimate access to. This is an unauthorized cross-stack read of deploy state, matching the "stack a token authorises versus a stack it touches" boundary called out as in-scope, and falls under the High impact category of "unauthenticated read of stack state ... or deploy output" relative to the token's intended scope.

### Likelihood Explanation
Any party who legitimately possesses one narrowly-scoped, low-privilege CCMenu/API token (a token intentionally designed to be shared/embedded, e.g. in CI status widgets) can trivially perform this by changing the `stack_id` route parameter. No additional secrets, GitHub access, or privileged account is required beyond one such existing token — likelihood is high once the target has any stack-scoped read token in circulation.

### Recommendation
Make `Api::CCMenuController#stack` honor the authenticated client's scope, mirroring `Api::BaseController#stacks`/`#stack`:

```ruby
def stack
  @stack ||= if current_api_client.stack_id?
               Stack.where(id: current_api_client.stack_id).from_param!(params[:stack_id])
             else
               Stack.from_param!(params[:stack_id])
             end
end
```

or simply reuse the inherited `stacks`/`stack` scoping instead of calling `Stack.from_param!` directly.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to Stack A: `stack_id = A`, `permissions = ['read:stack']` (this is exactly what `CCMenuUrlController#client` mints per-stack, intended only for Stack A's CCMenu URL).
2. Note its `authentication_token` (embedded in the generated `ccmenu_url`).
3. Request `GET /api/stacks/:B/ccmenu.xml?token=<Stack-A-token>` where `B` is any other stack id/param.
4. Observe that `require_permission :read, :stack` passes (token has `read:stack`), and `Api::CCMenuController#stack` resolves to Stack B via `Stack.from_param!(params[:stack_id])`, returning Stack B's deploy status instead of a 403/404 — confirming the token is not actually confined to Stack A.

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
