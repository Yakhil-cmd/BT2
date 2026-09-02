## Analog Validated: Api::CCMenuController breaks the "stack a token authorises" ↔ "stack it touches" binding

### Title
Stack-scoped `ApiClient` tokens can read the CCMenu build status of any stack, not just the stack they are scoped to - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` is supposed to scope every request to the stacks an `ApiClient` is authorised for via `stacks`/`stack`, but `Shipit::Api::CCMenuController` overrides `#stack` with an unscoped lookup, so any valid `read:stack` token - including one deliberately scoped to a single stack - can be replayed against `/api/stacks/*stack_id/ccmenu` for an arbitrary stack.

### Finding Description
The intended trust binding in the API is: "the set of stacks an `ApiClient` is authorised to touch" == "the set of stacks a given request can read/write," enforced by: [1](#0-0) 

`stacks` restricts the scope to `current_api_client.stack_id` when the client is stack-scoped, and `stack` derives the request's target from that restricted scope, so `Stack.from_param!` can only ever resolve a stack inside `stacks`.

`Shipit::Api::CCMenuController` inherits `BaseController` but locally redefines `#stack` to bypass that scoping entirely: [2](#0-1) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains `read:stack` (`ApiClient#check_permissions!`), it never checks `stack_id`: [3](#0-2) 

Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(params[:stack_id])`, a token that is scoped to `stack_id = X` (e.g. `here_come_the_walrus` fixture, `stack: shipit`) is authorised only for stack X by the model's own design, yet the CCMenu action will happily serve data for any other stack ID passed in the URL, because the "authorised stack" check the rest of the API relies on is never executed for this action.

The route confirms `stack_id` is a free-form URL segment supplied by the caller: `get '/ccmenu' => 'ccmenu#show', as: :ccmenu` under `scope '/stacks/*stack_id' ...`. [4](#0-3) 

### Impact Explanation
This is an authorization-escalation of a scoped `ApiClient` credential: a token that was only supposed to authorize reads of one stack's state is honored for *any* stack's state through the CCMenu endpoint, yielding the target stack's name, activity, last build status/label, last build time and web URL (per `test/controllers/api/ccmenu_controller_test.rb`, lines 20-31 confirming the returned XML fields, and the locked-stack disclosure at lines 41-45). This is exactly the "unauthenticated read of stack state" style escalation described in the High severity bucket - the attacker never needed a session, GitHub credentials, or any privilege beyond possessing one legitimately-issued, narrowly-scoped `read:stack` API token, and the DoS report's underlying lesson (a binding the code assumes is enforced everywhere is silently skipped in one code path) maps directly onto this: the "stack a token authorises" and "stack the CCMenu action touches" are supposed to be equal but are not, in this one controller.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` token - the exact kind of token the product deliberately hands out via the CCMenu-URL feature (`CCMenuUrlController#client`, intended to be embedded in third-party CI dashboards and thus at higher risk of leaking) - can trivially exploit this by changing the `stack_id` segment of the URL; no other tool or timing requirement is needed, unlike the front-running requirement in the original report.

### Recommendation
Make `Api::CCMenuController#stack` respect the same scoping as the rest of the API, e.g. `@stack ||= stacks.from_param!(params[:stack_id])` (reusing the inherited `stacks` helper) instead of calling `Stack.from_param!` directly, so a stack-scoped client can never resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. Create/possess an `ApiClient` scoped to `stack_id = shipit` with permission `read:stack` (as with the `here_come_the_walrus` fixture, or any token minted through the CCMenu-URL flow that is later scoped to a stack).
2. Send `GET /api/stacks/other-org/other-repo/other-env/ccmenu` with `Authorization: Basic <base64(token)>`.
3. `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` succeeds (token has `read:stack`), and `stack` resolves `other-org/other-repo/other-env` via the unscoped `Stack.from_param!`, returning that stack's build status/lock state even though the token's `stack_id` is `shipit`. [5](#0-4)

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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```
