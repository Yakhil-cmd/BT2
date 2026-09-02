### Title
Stack-scoped ApiClient token can read *any* stack's CCMenu status, bypassing its stack authorization scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the stack-lookup helper it inherits from `Shipit::Api::BaseController`, dropping the `ApiClient#stack_id` scoping that every other API endpoint relies on to bind a token to a single stack. As a result, a token that was issued (and is believed) to only authorize `read:stack` on one specific stack can be replayed against the CCMenu endpoint for a completely different stack.

### Finding Description
`Shipit::Api::BaseController` implements the scoping binding that ties an `ApiClient` token to the stack(s) it is allowed to touch: [1](#0-0) 
`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated client is stack-scoped (`stack_id?`), and `stack` resolves `params[:stack_id]` only from within that restricted relation via `stacks.from_param!`. This is the only place the stack-scope binding (`ApiClient.stack_id` == the stack a request may touch) is actually enforced — `require_permission!`/`check_permissions!` only checks the coarse `read:stack`/`write:stack`/... permission string, not which stack it applies to: [2](#0-1) 

`CCMenuController` breaks this binding by redefining `stack` to bypass the scoped `stacks` relation entirely, looking the stack up globally instead: [3](#0-2) 

Because `require_permission :read, :stack` (declared at the top of the controller) only calls `current_api_client.check_permissions!('read', 'stack')`, and the overridden `stack` method never consults `current_api_client.stack_id`, any valid, authenticated `read:stack`-permitted `ApiClient` token — even one explicitly created with `stack_id` set to Stack A — can be used with `params[:stack_id]` pointing at Stack B and will successfully render Stack B's CCMenu project status: [4](#0-3) 

The binding that should hold is: `ApiClient.stack_id (the stack the token authorizes) == stack (the stack the request touches)`. Before the request: the token is scoped to Stack A only, per `stacks`/`stack` in `BaseController`. After the request against `CCMenuController#show` with `stack_id=B`: the binding is silently dropped and Stack B's data is returned, because this controller's `stack` accessor never intersects with `current_api_client.stack_id`.

### Impact Explanation
This grants unauthenticated-scope read access to another stack's deploy/task state (last deploy id, running status, timestamps) rendered as the CCMenu XML project status — data the token holder was never authorized to see for that stack. This matches the High-severity class of "unauthenticated read of stack state, task streams or deploy output" via an authorization-scope binding break, since the token's scope (the credential/repository binding) is what should gate which stack's state can be read, and that binding is violated here.

### Likelihood Explanation
Any party in possession of a stack-scoped API token (e.g. a token intentionally scoped narrowly to reduce blast radius, generated e.g. via `CCMenuUrlController`/settings UI flows that mint `ApiClient` records) can trivially trigger this by changing the `stack_id` route/query parameter of the CCMenu request — no additional secret or privilege escalation is required beyond having any valid token with `read:stack` permission. This is a straightforward parameter-substitution attack requiring only a single legitimate, low-privilege credential.

### Recommendation
Remove the controller-local override of `stack` in `Shipit::Api::CCMenuController` (or reimplement it to go through the inherited, scope-checked `stacks` relation, e.g. `stacks.from_param!(params[:stack_id])`) so that stack-scoped `ApiClient` tokens cannot be used to access stacks outside of their authorized `stack_id`.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` and `stack_id: A.id` (e.g. via the "CCMenu Client" flow in `CCMenuUrlController`, or any admin-created scoped client).
2. Compute its `authentication_token` (available if the token was ever exposed, e.g. through the ccmenu URL feature or an admin panel).
3. Issue `GET /api/stacks/:owner/:repo_B/:env_B/ccmenu?token=<Stack A's token>` where `owner/repo_B/env_B` identifies Stack B (a stack unrelated to the token's `stack_id`).
4. Observe that `CCMenuController#authenticate_api_client` succeeds (`ApiClient.authenticate(params[:token])` finds the client, permission check passes because the client has `read:stack`), and `CCMenuController#stack` resolves Stack B directly via `Stack.from_param!(params[:stack_id])` — never checking that `current_api_client.stack_id == Stack B.id` — returning Stack B's CCMenu project XML (deploy status/output) despite the token only being authorized for Stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-26)
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

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
