### Title
CCMenu Controller Bypasses ApiClient Stack Scoping, Allowing Cross-Stack Status Disclosure - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` enforces that a scoped `ApiClient` (one bound to a single `Stack` via `belongs_to :stack`) can only reach the stack it is bound to, by resolving the target stack through the `stacks` scope. `Shipit::Api::CCMenuController` overrides the `stack` lookup to use `Stack.from_param!(params[:stack_id])` directly, completely bypassing that scope. The permission check that remains (`require_permission :read, :stack`) only validates that the token *has* the `read:stack` permission string — it never validates that the permission applies to the requested stack. This reproduces the PoolTogether bug class: an authorization decision is made against one value (the permission list on the token) while the actual privileged action is performed against a different, unchecked value (an arbitrary `stack_id` supplied in the request).

### Finding Description
`BaseController` defines the canonical, scope-respecting resolution of "which stack this client may touch": [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the client is bound to a stack, and `stack` is derived from that restricted relation. This is the mechanism the engine relies on to keep a stack-scoped `ApiClient` from touching other stacks — confirmed by the test "an api client scoped to a stack will only see that one stack" in `test/controllers/api/stacks_controller_test.rb`.

`CCMenuController`, however, redefines `stack` to resolve directly against the full, unscoped `Stack` model, and separately overrides authentication to accept a bare token param instead of the standard basic-auth flow: [2](#0-1) 

The only remaining authorization gate is:
```ruby
require_permission :read, :stack
```
which calls `ApiClient#check_permissions!`: [3](#0-2) 

This checks only that `"read:stack"` is present in `permissions` — it takes no `stack_id` argument and cannot know which stack is being requested. Because `stack` in `CCMenuController` is resolved from `params[:stack_id]` against the entire `Stack` table rather than through `stacks` (which is what actually enforces `current_api_client.stack_id`), **any token that carries `read:stack` permission — regardless of which single stack it was minted for — can be replayed with a different `stack_id` in the URL to read another stack's build/deploy status.**

The equality that should hold but is broken:
`stack the ApiClient's stack_id authorizes == stack the ApiClient's request actually touches`

Before the flaw: enforced via `stacks.from_param!(params[:stack_id])` everywhere in `Api::BaseController` subclasses.
After: `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])`, an unscoped lookup, so the LHS/RHS binding no longer holds for this one controller.

### Impact Explanation
This is an unauthenticated-appropriate, unprivileged read: the CCMenu token is handed out for embedding in build-radiator / CI dashboard tools (see `CCMenuUrlController`, which mints such tokens) and is not a session-bound credential. An attacker in possession of *any* valid CCMenu (or otherwise `read:stack`-scoped) token — even one legitimately scoped by an administrator to a single, low-sensitivity stack — can enumerate `stack_id` values and pull the `lastBuildStatus`, `activity` (building/sleeping), `lastBuildTime`, `lastBuildLabel`, and deploy/lock status of every other stack in the installation, including ones the token was never meant to access. That matches the "unauthenticated read of stack state, task streams or deploy output" High-impact category: information about deploy activity and stack lock/merge status across the whole Shipit instance leaks to a party who was authorized for only one stack.

### Likelihood Explanation
Likelihood is high for anyone who already holds one scoped, `read:stack`-only token (e.g., a build-radiator viewer, a low-privilege integration), since exploitation requires nothing beyond changing a URL query parameter (`stack_id`) — no additional credentials, no signature forgery, and no session. The only prerequisite is possessing any valid CCMenu-style token, which by design is meant to be narrowly scoped to a single stack and is often embedded in less-trusted client-side dashboards.

### Recommendation
Have `CCMenuController#stack` resolve through the same scope-respecting helper the rest of `Api::BaseController` uses (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction is applied consistently. Alternatively, explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering the CCMenu XML.

### Proof of Concept
1. An administrator scopes an `ApiClient` (e.g. via the CCMenu integration flow in `CCMenuUrlController`) to `Stack` A with permission `read:stack`, and shares the resulting CCMenu URL/token with a monitoring tool.
2. The holder of that token requests:
   `GET /api/1.0/stacks/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/cc_menu.xml?token=<TOKEN_SCOPED_TO_STACK_A>`
3. `authenticate_api_client` (overridden in `CCMenuController`) accepts the token via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because the token has `read:stack` in its `permissions` array — it never inspects `stack_id`.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` against Stack B (not restricted to Stack A), and the controller renders Stack B's build/deploy status in the XML response, even though the token was only ever authorized for Stack A. [4](#0-3) [1](#0-0)

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
