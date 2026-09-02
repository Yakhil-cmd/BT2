### Title
API stack-scoped tokens bypass their stack restriction via `CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper defined in `Shipit::Api::BaseController` and, in doing so, drops the scoping that restricts a stack-bound `ApiClient` token to only the stack it was issued for. This breaks the trust binding: *the stack a token authorises* (`ApiClient#stack_id`) versus *the stack the request actually touches* (`params[:stack_id]`).

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting stack lookup: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is bound to a specific stack (`stack_id?`), and only falls back to `Stack.all` for unscoped ("global") clients. Every other API controller that needs to load a stack (`Api::StacksController`, etc.) relies on this scoped `stacks.from_param!(params[:stack_id])`.

`Api::CCMenuController`, however, defines its own private `stack` method that calls `Stack.from_param!` directly on the unscoped `Stack` model, completely bypassing the `stacks` scoping helper: [2](#0-1) 

The controller's only authorization gate is: [3](#0-2) 

`require_permission :read, :stack` only checks that the token carries the generic `read:stack` permission string via `ApiClient#check_permissions!`: [4](#0-3) 

It never checks whether `current_api_client.stack_id` matches the `stack_id` in the request — that check only happens implicitly through the `stacks` scoping helper, which `CCMenuController` does not use.

Equality broken:
- Before: `stack_read_by_client == current_api_client.stack_id` (enforced everywhere via `stacks.from_param!`)
- After (via `CCMenuController`): `stack_read_by_client == params[:stack_id]` (any stack, regardless of `current_api_client.stack_id`)

### Impact Explanation
Any `ApiClient` token that has been deliberately scoped to a single stack (a common pattern, e.g. the `here_come_the_walrus` fixture and the token created by `CCMenuUrlController` for CCTray/CI-status integrations, `app/controllers/shipit/ccmenu_url_controller.rb`) and merely carries the `read:stack` permission can be used to read the deploy/build status (`show` action renders `deploys_and_rollbacks.last`) of **any** stack in the installation, not just the one it was authorized for. This is a cross-stack unauthorized read of stack state (deploy status/output), matching the High-severity category of "unauthenticated read of stack state, task streams or deploy output" for stacks outside the token's authorized scope.

### Likelihood Explanation
Any holder of a valid, stack-scoped, read-only API token (which Shipit hands out routinely for CI dashboards / CCTray integrations via `CCMenuUrlController`) can trivially exploit this by changing the `stack_id` in the URL — no additional privileges, no write access, and no social engineering required. This is a straightforward, deterministic bypass, not a race condition or edge case.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController` instead of querying `Stack` directly:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

removing the override entirely (or ensuring it still funnels through `current_api_client`'s stack scoping) so a stack-scoped token cannot resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` (e.g. via `CCMenuUrlController#fetch`, which creates `ApiClient.create_with(permissions: %w[read:stack])...`, or directly with `stack: stack_a`).
2. Using that token/URL (`api_stack_ccmenu_url(stack_id: stack_a, token: ...)`), simply substitute Stack B's id/slug for `stack_id` in the request: `GET /api/stacks/:stack_b_id/cc_menu.xml?token=<stack_a_scoped_token>`.
3. `authenticate_api_client` succeeds (valid token), `require_permission :read, :stack` succeeds (token has `read:stack`), and `stack` resolves via `Stack.from_param!(params[:stack_id])` to Stack B regardless of the token's `stack_id`.
4. The response renders Stack B's latest deploy/rollback status (`app/views/shipit/ccmenu/project`), exposing another stack's CI/deploy state to a token that was never authorized for it.

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
