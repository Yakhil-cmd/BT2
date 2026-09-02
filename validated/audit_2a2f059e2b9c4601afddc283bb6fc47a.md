### Title
Stack-scoped API client authorization bypass in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the `stack` accessor to resolve the stack directly from the request parameter instead of going through the stack-scoping helper defined in `Api::BaseController`, breaking the invariant that a stack an `ApiClient` token is scoped to must equal the stack the request actually touches.

### Finding Description
`Api::BaseController` implements two related helpers meant to enforce that a stack-scoped `ApiClient` can only ever operate on the stack it is bound to: [1](#0-0) 

`stacks` restricts the queryable relation to `current_api_client.stack_id` when the client is scoped, and `stack` resolves the requested `params[:stack_id]` only from within that restricted relation. Every other API controller (`Api::StacksController`, etc.) relies on this `stack`/`stacks` pair to look up the target stack, so the client's `stack_id` binding is enforced consistently.

`Api::CCMenuController`, however, defines its own private `stack` method that bypasses this entirely, resolving the record straight from the unrestricted `Stack` model: [2](#0-1) 

Permission enforcement for this controller is only `require_permission :read, :stack`, which checks that the client has a generic `read:stack` permission string, independent of which specific stack it is bound to: [3](#0-2) 

`ApiClient` is a first-class model with an optional `stack` association (used by fixtures/tests to model per-stack tokens), so the intended security invariant is: **`current_api_client.stack_id == stack.id`** whenever the client is stack-scoped. `Api::CCMenuController#stack` never checks this equality — any client holding a `read:stack`-permissioned token, regardless of its own `stack_id`, can pass an arbitrary `stack_id` param and the controller will happily load and render that stack's CI/build data.

This is the exact bug class from the external report: a value that is supposed to gate/authorize the operation (the token's bound stack) is never actually enforced against the value the code operates on (the stack looked up from the request), just as the contract's `initialize`/`deployAccount` never wired `msg.value` into the actual `call` value.

### Impact Explanation
Any holder of a valid stack-scoped `ApiClient` token (e.g. tokens intentionally created for embedding in third-party CI dashboard tools, since `CCMenuController#authenticate_api_client` also accepts the token via a plain query-string parameter, making leakage more likely) can read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock status, etc.) of every other stack in the Shipit instance, not just the one it was scoped to. This is an authorization-scope escalation resulting in unauthorized read of stack state, matching the High-severity criterion "unauthenticated/unauthorized read of stack state, task streams or deploy output."

### Likelihood Explanation
Likelihood is Medium-High: exploitation requires only possession of any valid `ApiClient` token with `read:stack` permission (regardless of its intended stack scope) and knowledge/guessing of another stack's `to_param` (typically `owner/repo/environment`, which is often public/predictable). No privileged account, session, or GitHub credentials are needed — only a legitimately-issued, narrowly-scoped API token, which is the precise attacker model the stack_id scoping mechanism was built to contain.

### Recommendation
Make `Api::CCMenuController#stack` resolve through the inherited `stacks`/`stack` scoping helper (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped clients cannot address stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ["read:stack"]` and `stack_id` set to Stack A's id (e.g. via console/seed, mirroring the fixture pattern in `test/fixtures/shipit/api_clients.yml`).
2. Compute its `authentication_token` (`ApiClient#authentication_token`) — an HMAC-signed client id, valid for any endpoint that authenticates it.
3. Send:
   `GET /api/:stack_id_of_stack_B/ccmenu.xml?token=<stack-A-scoped-token>`
4. `authenticate_api_client` in `CCMenuController` accepts the token; `require_permission :read, :stack` passes (the client does have `read:stack`); `stack` resolves `Stack.from_param!("stack_id_of_stack_B")` with no scoping check.
5. The response renders Stack B's build/deploy status (`lastBuildStatus`, `lastBuildLabel`, etc.), even though the token was only meant to authorize Stack A. [4](#0-3)

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
