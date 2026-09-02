### Title
Stack-scoped API client tokens can read CI/build status of any stack via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts every stack-scoped `ApiClient` to only the stack it was issued for by filtering the queryable stack set through `stacks` before resolving `params[:stack_id]`. `Api::CCMenuController` re-implements stack resolution and skips that scoping filter entirely, so a token that is only supposed to authorize `read:stack` on one specific stack can be replayed with a different `stack_id` to read another stack's build/CI status.

### Finding Description
`Api::BaseController#stack` resolves the target stack only from the client's authorized set: [1](#0-0) 

This enforces the binding: `stack the token authorizes == stack the request touches`, by scoping `Stack.where(id: current_api_client.stack_id)` when the client is stack-restricted, before calling `from_param!`.

`Api::CCMenuController`, however, overrides `stack` to bypass that scoping entirely, resolving directly against the global `Stack` relation using the attacker-controlled `params[:stack_id]`: [2](#0-1) 

It only declares a generic permission requirement (`read:stack`), which `ApiClient#check_permissions!` validates as a *type* of permission, not as a check that the specific `stack_id` in the request matches the `stack_id` the token was scoped to: [3](#0-2) [4](#0-3) 

Because `ApiClient belongs_to :stack, optional: true`, tokens can legitimately be scoped to a single stack: [5](#0-4) 

and `BaseController#stacks` is exactly the mechanism meant to enforce that scope for every other controller in the `Api` namespace: [6](#0-5) 

`Api::CCMenuController#authenticate_api_client` additionally allows the token to be supplied as a URL query-string parameter rather than an `Authorization` header, matching how CCMenu URLs are generated (`ccmenu_url_controller.rb` embeds `token` in the query string): [7](#0-6) 

This is the same class of bug as the reported `claimAndCompound` issue: an action ("read this stack's status") is executed on behalf of an authenticated actor (the API client) without checking that the actor is actually authorized ("opted-in") for the specific target (`stack_id`) it is acting on — the authorization check (`read:stack`) is verified, but the binding between the *token's authorized scope* and the *stack actually touched* is not.

### Impact Explanation
A holder of any valid, stack-scoped `read:stack` API-client token (e.g., one legitimately created and shared for a single stack's CCMenu integration) can enumerate and read the build/CI status, last build label, and deploy activity of **every** stack in the Shipit instance, not just the one the token was authorized for, by supplying a different `stack_id` to `/api/*stack_id/ccmenu`. This is an unauthenticated-scope escalation / unauthorized read of stack state across stacks the token holder has no legitimate access to, matching the "High" impact category (escalation into authorization scope, unauthenticated/unauthorized read of stack state).

### Likelihood Explanation
Any party who legitimately possesses one restricted CCMenu/API token (a common, low-privilege integration credential meant to be embedded in third-party CI dashboard tools) can trivially perform this by changing the `stack_id` path segment on an already-authenticated request. No additional privileges, secrets, or GitHub access are required beyond possessing one valid stack-scoped token.

### Recommendation
Have `Api::CCMenuController#stack` reuse the scoped `stacks` collection (`stacks.from_param!(params[:stack_id])`) exactly as `BaseController` does for every other resource, instead of resolving against the unscoped `Stack` relation.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (e.g., via `Api::StacksController#create` / `ApiClientsController`, or the CCMenu URL flow if it is scoped to a stack).
2. Authenticate to `GET /api/<stack-B-param>/ccmenu?token=<clientA-token>` (or via Basic auth header) where stack B is a different stack the client was never granted access to.
3. Because `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly (bypassing the `stacks` scoping used elsewhere), the request succeeds and returns stack B's CI/build XML status, despite the token only being authorized for stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-7)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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
