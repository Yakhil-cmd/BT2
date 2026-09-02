### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-restricted token to read another stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` scoped to a specific stack (`stack_id` set) can only resolve `stack` from the subset of stacks it is authorized for, via `stacks.from_param!` where `stacks` is filtered by `current_api_client.stack_id`. [1](#0-0)  `Shipit::Api::CCMenuController` overrides the `stack` resolution to use `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` model, completely bypassing the token's stack restriction, while still only checking the unscoped `read:stack` permission. [2](#0-1) 

### Finding Description
This mirrors the M-36 pattern: a binding that is supposed to hold between an authorization credential and the resource it is scoped to (`stack` authorized by an `ApiClient`'s `stack_id` == `stack` actually acted upon) is inconsistently enforced across code paths. `ApiClient#stack_id` is meant to restrict a token so it can only see/act on one particular `Stack`, and the normal `BaseController#stack` helper enforces this by scoping `Stack.where(id: current_api_client.stack_id)` before resolving `params[:stack_id]`. [1](#0-0)  `CCMenuController`, however, declares `require_permission :read, :stack`, which only calls `current_api_client.check_permissions!(:read, :stack)` — a check that only inspects the string permission list (`permissions.include?("read:stack")`) and has no notion of which specific stack the token is bound to. [3](#0-2)  The controller then defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` — bypassing the `stacks` scoping helper entirely — so `params[:stack_id]` is resolved against every `Stack` in the database, not just the one the token is bound to. [4](#0-3) 

Concretely: before the attack, an `ApiClient` created with `stack_id` set to Stack A and permission `read:stack` (e.g. via `Shipit::CCMenuUrlController#client`, which creates exactly such a client with `permissions: %w[read:stack]` scoped implicitly by usage on a given stack's URL) is intended to only ever expose Stack A's status. [5](#0-4)  After the attack — the holder of that token requests `GET /stacks/:owner/:repo/:env/ccmenu.xml?token=<tokenA>` but supplies Stack B's `stack_id` param — the controller resolves `stack` to Stack B via the unscoped `Stack.from_param!`, and `check_permissions!(:read, :stack)` still passes because it never inspects which stack is being accessed. [6](#0-5) 

### Impact Explanation
The `show` action renders Stack B's latest deploy/rollback record (id, ended_at, running state, and via the `ccmenu/project` view, deploy status/output metadata) to a caller whose token was never authorized for Stack B. [7](#0-6)  This is an unauthorized cross-stack read of deploy state using a token that is supposed to be confined to a single stack — matching the "unauthenticated read of stack state ... deploy output" High-impact category, since the credential presented is not authorized for the stack whose state is disclosed.

### Likelihood Explanation
Any holder of a legitimately-issued, single-stack-scoped CCMenu token (these tokens are handed out to third-party CI dashboard tools, e.g. CCMenu clients, and embedded in URLs) can trivially trigger this by changing the `stack_id` route segment/param to a different stack while keeping their own valid token — no additional privilege, secret, or session is required. This requires only possession of a normal `ApiClient` token scoped to `read:stack`+ a `stack_id`, which is the CCMenu feature's intended, unprivileged-facing distribution mechanism.

### Recommendation
Have `Shipit::Api::CCMenuController#stack` resolve through the scoped `stacks` helper from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that an `ApiClient` with a `stack_id` can never resolve a different stack regardless of the `read:stack` permission check.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` and `stack_id: StackA.id` (this is exactly what `CCMenuUrlController#client` does). [5](#0-4) 
2. Obtain the token via `client.authentication_token`, e.g. from the generated `ccmenu_url`.
3. Send `GET /stacks/:owner/:repoB/:envB/ccmenu.xml?token=<tokenA>` where `repoB`/`envB` identify Stack B (unrelated to Stack A).
4. `CCMenuController#authenticate_api_client` authenticates the token successfully (it is valid), `require_permission :read, :stack` passes because `check_permissions!` only checks the permission string, and `stack` resolves to Stack B via the unscoped `Stack.from_param!(params[:stack_id])`. [6](#0-5) 
5. Response renders Stack B's latest deploy/rollback status — data the token holder was never authorized to see.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
