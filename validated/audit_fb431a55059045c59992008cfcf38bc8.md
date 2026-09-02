### Title
`Api::CCMenuController` bypasses per-token stack scoping, allowing a stack-restricted `ApiClient` to read any stack's deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::BaseController` implements a permission model where an `ApiClient` can be scoped to a single stack via `stack_id`, and all stack lookups are expected to go through the `stacks` helper, which restricts the queryable set to that one stack. `Api::CCMenuController` overrides the `stack` accessor to bypass this scoping entirely, looking the stack up globally instead of through the client's authorized scope, so the "stack a token authorizes" and "stack it touches" bindings diverge.

### Finding Description
`Api::BaseController` defines the intended scoping mechanism: [1](#0-0) 

`stacks` restricts the visible set to `current_api_client.stack_id` when the client is scoped, and `stack` is supposed to be derived from that restricted relation via `stacks.from_param!`. This is the binding: an `ApiClient` created with `stack: shipit` (see `ApiClient#stack_id?` in `app/models/shipit/api_client.rb`) is meant to be able to act only on that one stack.

`Api::CCMenuController`, however, overrides `stack` to bypass the `stacks` scope entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, rather than `stacks.from_param!(params[:stack_id])`. The only permission check applied is the scope-agnostic `require_permission :read, :stack`: [3](#0-2) 

`check_permissions!` only validates the operation/scope pair (`read:stack`), not which specific stack the token is bound to: [4](#0-3) 

So a token that was issued with `read:stack` permission and a specific `stack_id` (e.g. the "CCMenu Client" created per-stack in `CCMenuUrlController`) is authorized only for that one stack: [5](#0-4) 

but because `CCMenuController#stack` ignores the client's `stack_id` scope, that same token, when the attacker (any holder of that token/URL, since `CCMenuUrlController#fetch` returns a shareable URL with the token embedded) simply changes `stack_id` in the request path, can fetch CCTray XML deploy status for any other stack in the installation, including private/unrelated repositories' stacks - not just the one it was scoped and intended for.

### Impact Explanation
This breaks the "stack a token authorizes vs. stack it touches" binding: a token explicitly scoped to a single stack via `ApiClient#stack_id` gains read access to the deploy state (`latest_deploy`, running status, last build outcome) of every stack in the Shipit installation. This is an authorization-scope escalation resulting in unauthorized read of stack state across repositories the token holder was never granted access to - matching the High-impact category of "escalation into `Shipit.github_teams` authorization" analog and "unauthenticated/unauthorized read of stack state, task streams or deploy output" for stacks outside the token's granted scope.

### Likelihood Explanation
The CCMenu URL (containing the bearer token) is designed to be handed out/embedded in third-party CI dashboard tools (CCTray clients), which increases the chance of it leaking to a context where an attacker could manipulate the `stack_id` path segment. Exploitation requires only possession of a valid, even narrowly-scoped, `read:stack` API token/URL - no privilege escalation, no additional authentication bypass, and no code execution is needed to enumerate other stacks' deploy status.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped `stacks` relation instead of the global `Stack` model, i.e. `stacks.from_param!(params[:stack_id])`, consistently with `Api::BaseController#stack`, so that stack-scoped `ApiClient` tokens cannot read data outside their authorized stack.

### Proof of Concept
1. Create a stack-scoped `ApiClient` for `stack: shipit_a` with `permissions: ['read:stack']` (as done by `CCMenuUrlController#client`), and obtain its CCMenu URL/token.
2. As the token holder, send `GET /api/stacks/:other_owner/:other_stack/cc_menu?token=<token>` where `:other_owner/:other_stack` refers to a different stack the token was never scoped to.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (app/controllers/shipit/api/ccmenu_controller.rb:30) instead of the scoped `stacks.from_param!`, the request succeeds and returns the CCTray XML deploy status for the unrelated stack, despite the token being provisioned only for `shipit_a`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
