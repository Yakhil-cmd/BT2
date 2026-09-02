## Analog Vulnerability Confirmed

### Title
Stack-scoped API tokens can read CI status of any stack via CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution method inherited from `BaseController` in a way that removes the per-token stack scoping, letting any authenticated `ApiClient` — including one explicitly scoped to a single stack — fetch build/deploy status for every stack in the installation.

### Finding Description
`Shipit::Api::BaseController` is designed so that a scoped `ApiClient` (one with `stack_id` set) can only resolve stacks through the `stacks` relation, which filters by `current_api_client.stack_id`: [1](#0-0) 

Every other API controller (e.g. `StacksController#stack`, `HooksController#stack_id`) relies on this scoped `stacks`/`stack` helper, so a token limited to one stack cannot touch another: [2](#0-1) [3](#0-2) 

`CCMenuController`, however, redefines `stack` to resolve directly against the unscoped `Stack` model, bypassing the `current_api_client.stack_id` filter entirely: [4](#0-3) 

The only access control left is `require_permission :read, :stack`, which merely checks that the token carries the `read:stack` permission string — it never checks that the requested `stack_id` matches the stack the token was authorized for: [5](#0-4) [6](#0-5) 

This reproduces the report's bug class: the binding "stack a token authorizes == stack a token touches" is broken. Before the request, the token is only entitled to read the one stack referenced by `ApiClient#stack_id`; after hitting `CCMenuController#show`, it can read build status, last deploy state, lock state, and web URL for **any** stack in the deployment, because the controller substitutes the caller-supplied `params[:stack_id]` for the token's actual authorized stack without validation.

### Impact Explanation
A token deliberately scoped to a single, low-sensitivity stack (e.g. created via `CCMenuUrlController#fetch`, which always creates a `read:stack`-only client tied to one stack) can be used to read the CI/deploy status — including lock reason, last build result, and last deploy label — of any other stack in the installation, including ones the token holder was never granted visibility into. This is an authorization-scope escalation matching the "escalation into `Shipit.github_teams` authorization" / unauthorized read of stack state class of High-impact findings.

### Likelihood Explanation
Any holder of a valid, narrowly-scoped `ApiClient` token (for example, the read-only CCMenu token that `CCMenuUrlController#fetch` mints for ordinary logged-in users) can trigger this by simply changing the `stack_id` path parameter — no additional privilege, signature forgery, or race condition is required.

### Recommendation
Remove the `stack` override in `CCMenuController` and resolve the stack through the scoped `stacks` relation (as `StacksController` and `HooksController` do), so a client's `stack_id` restriction is enforced consistently across every API controller. Additionally, `ApiClient#check_permissions!` (or a shared before_action) should verify that when `current_api_client.stack_id?` is true, the resolved stack's id equals `current_api_client.stack_id`, rather than relying on each controller to re-implement scoping correctly.

### Proof of Concept
1. As a logged-in user, visit any stack page to mint a scoped CCMenu token: `GET /:stack_a/ccmenu_url` → returns a token whose `ApiClient#stack_id == stack_a.id` and `permissions == ["read:stack"]` (see `app/controllers/shipit/ccmenu_url_controller.rb`).
2. Using that token via HTTP Basic Auth (or `?token=`), call `GET /api/:stack_b/ccmenu.xml` for an unrelated `stack_b`.
3. The response returns `stack_b`'s CCMenu project XML (name, `lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock status), even though the token's `stack_id` is `stack_a.id` — confirming the scoping bypass in `app/controllers/shipit/api/ccmenu_controller.rb`.

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L46-52)
```ruby
      def hooks
        Hook.where(stack_id:)
      end

      def stack_id
        stack.id if params[:stack_id].present?
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
