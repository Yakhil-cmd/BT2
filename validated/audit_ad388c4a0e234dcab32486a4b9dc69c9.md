### Title
CCMenu API controller bypasses per-stack token scoping, allowing a stack-scoped `ApiClient` to read any stack's CI/build status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` enforces the binding "the stack an `ApiClient` is authorized for == the stack a request may touch" by resolving stacks through the `stacks` scope, which is filtered by `current_api_client.stack_id` when present [1](#0-0) . Every other API resource controller (e.g. `Api::StacksController#stack`) honors this by calling `stacks.from_param!(params[:id])` [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, completely skipping the `stacks` scoping helper [3](#0-2) .

### Finding Description
`ApiClient` supports being scoped to a single stack via the optional `stack` association / `stack_id` column, and `BaseController#stacks` is the single chokepoint meant to enforce that scope for every resource lookup [4](#0-3) [1](#0-0) . `CCMenuController` only checks the client's generic `read:stack` permission via `require_permission :read, :stack` [5](#0-4) , and `check_permissions!` only verifies the operation/scope string is in the client's `permissions` array — it never validates which specific stack the client is bound to [6](#0-5) . Because `CCMenuController#stack` re-implements the lookup with the unscoped `Stack.from_param!` instead of the inherited scoped `stacks.from_param!`, the stack_id-based restriction that every sibling controller relies on (`Api::StacksController#stack`) is silently dropped for this one endpoint [7](#0-6)  vs. [2](#0-1) .

This mirrors the `L1Staking` pattern: a bound-checking loop/lookup (`stacks.from_param!` gated on `stakerIndexes`-equivalent `stack_id`) is supposed to apply uniformly, but one specific code path re-implements the lookup with a different, unscoped source of truth (`Stack.from_param!`, analogous to `stakerSet[i-1]` being read outside the intended index range), breaking the equality "stack the token authorizes == stack the request touches."

### Impact Explanation
Any valid `ApiClient` token restricted to a single stack (`stack_id` set, `read:stack` permission) can be replayed against `GET /api/stacks/:stack_id/ccmenu` for an arbitrary `stack_id` and will successfully render that other stack's CCMenu XML — including stack name, `lastBuildStatus`, `lastBuildLabel`, and `webUrl` (deploy/task permalink) [8](#0-7) . This is an unauthorized read of stack/build state for a stack the token was never scoped to, which falls under the "High - unauthenticated/unauthorized read of stack state, task streams or deploy output" category, since the scoping boundary the token is supposed to enforce is bypassed.

### Likelihood Explanation
Exploitation only requires possession of any valid stack-scoped API token with `read:stack` permission (no admin/GitHub access needed) and knowledge/guessing of another stack's `to_param` (slug), which is not treated as a secret elsewhere in the app (stack slugs are visible in URLs). The controller can be authenticated via a `token` query-string parameter as well as basic auth, making it trivial to script [9](#0-8) .

### Recommendation
Change `Api::CCMenuController#stack` to use the inherited scoped lookup, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, matching `Api::StacksController#stack`, so that any `ApiClient` restricted via `stack_id` cannot resolve a stack outside its authorized scope.

### Proof of Concept
1. As an admin, create/observe an `ApiClient` with `stack_id` set to stack A and `permissions: ['read:stack']` (e.g. via the CCMenu URL flow that creates a scoped read-only client).
2. Using that client's `authentication_token`, issue: `GET /api/stacks/<stack-B-slug>/ccmenu?token=<token>` where stack B is a different stack the client was never scoped to.
3. Observe the response returns HTTP 200 with stack B's CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc.), despite the client's `stacks` scope (per `BaseController#stacks`) being limited to stack A — because `CCMenuController#stack` never calls that scoped method.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

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

**File:** app/models/shipit/api_client.rb (L4-9)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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
