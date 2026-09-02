## Finding

### Title
Stack-scoped ApiClient token authorizes CCMenu status reads of any stack via `Api::CCMenuController#stack` bypassing scope check - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The Hats Protocol bug is a "binding not re-enforced after action" issue: a value (`linkedTreeRequests`) that grants future authority survives an action (`unlinkTopHatFromTree`) that was supposed to revoke all outstanding authority. The direct analog in shipit-engine is a binding that is supposed to be enforced (an `ApiClient`'s `stack_id` scope) but is silently bypassed in one specific controller, letting a token authorized for stack A read state for any stack B.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting accessor for the current stack: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the authenticated `ApiClient` is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted set. This is the binding: `ApiClient#stack_id` (the stack the token authorizes) must equal (or be a superset containing) the stack the request touches.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

Instead of calling the inherited `stacks.from_param!(...)`, it calls `Stack.from_param!(params[:stack_id])` directly against the entire `Stack` table, ignoring `current_api_client.stack_id`. The `require_permission :read, :stack` guard only checks that the token has the generic `read:stack` permission string via `ApiClient#check_permissions!`: [3](#0-2) 

`check_permissions!` never compares `stack_id` to the resolved `stack`; scope enforcement is expected to happen entirely inside the `stack` accessor, exactly as `BaseController` does for every other API controller (e.g. `Api::StacksController` relies on the same `stacks`/`stack` helpers).

**Before vs. after the binding is respected:**
- Before (intended, as in `BaseController`): `token.stack_id == requested_stack.id` (or token unscoped) must hold for any stack data to be returned.
- After (in `CCMenuController`): the equality is never checked; `requested_stack.id` can be any value regardless of `token.stack_id`.

### Impact Explanation
An `ApiClient` deliberately scoped to one stack (e.g. created via the UI's `CCMenuUrlController#client`, or via the API with `stack_id` set to restrict blast radius of a leaked token) can be replayed against `Api::CCMenuController#show` with a different `stack_id` and will successfully render that other stack's CCMenu XML — deploy/build status, last activity, lastBuildLabel, webUrl, and `NoDeploy` fallback details. This is an authenticated read of stack state for a stack the token was never authorized to see, i.e. unauthorized cross-stack read of deploy output/status, matching the "High" impact category (unauthenticated/out-of-scope read of stack state or deploy output) since the enforcement that should gate it is bypassed.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (a routine, low-privilege credential intentionally issued with a narrow `stack_id` scope, e.g. for CI status badges) can trigger this by simply changing the `stack_id` route/query param on a request to `Api::CCMenuController#show`. No additional secrets, elevated roles, or GitHub write access are required beyond possessing one legitimately-scoped token.

### Recommendation
Remove the overriding `stack` (and ideally `authenticate_api_client`) methods in `Api::CCMenuController`, or reimplement them to reuse the base class's scoped `stacks` method:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that `current_api_client.stack_id` is always honored, consistent with every other API controller in `app/controllers/shipit/api/**`.

### Proof of Concept
1. Create/obtain a stack-scoped `ApiClient` with `permissions: ['read:stack']` and `stack_id` pointing to Stack A (as `CCMenuUrlController#client` does, or via the `Api::StacksController`/admin UI setting a `stack` on the client).
2. Compute its `authentication_token` (`ApiClient#authentication_token`).
3. Request `GET /api/stacks/:stack_B_param/ccmenu.xml?token=<token>` where `stack_B` is a different, unrelated stack.
4. `Api::CCMenuController#authenticate_api_client` accepts the token via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because the token has the `read:stack` permission string; `stack` resolves `Stack.from_param!(params[:stack_id])` against Stack B directly, bypassing the `current_api_client.stack_id` restriction present in `BaseController#stacks`. The response renders Stack B's deploy/build status even though the token was only ever authorized for Stack A. [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/api_client.rb (L34-46)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
    end

    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
  end
```
