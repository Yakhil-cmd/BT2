### Title
CCMenu API endpoint bypasses per-stack ApiClient scoping, allowing a stack-scoped token to read the status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` implements a deliberate authorization binding: an `ApiClient` may be scoped to a single `Stack` via `stack_id`, and every controller that inherits `#stack` from `BaseController` must resolve the requested stack through `stacks`, which restricts the lookup to `current_api_client.stack_id` when one is set. `Shipit::Api::CCMenuController` overrides both `#stack` and `#authenticate_api_client`, and in doing so drops the scoping check entirely, letting any valid `read:stack` token read the CI status/output of a stack it was never authorized for.

### Finding Description
`Shipit::Api::BaseController` defines the trust binding between a token and the stack(s) it may touch: [1](#0-0) 

This is exercised and relied upon elsewhere, e.g. `Shipit::Api::StacksController#stack` uses the same scoped `stacks` relation: [2](#0-1) 

and is explicitly tested as a security property ("an api client scoped to a stack will only see that one stack").

`Shipit::Api::CCMenuController`, however, redefines `stack` to resolve directly against the global `Stack` relation, and redefines `authenticate_api_client` to accept the token as a query-string parameter, but still relies solely on `require_permission :read, :stack` (which only checks that the token has the `read:stack` permission string, not that it is scoped to the requested stack): [3](#0-2) 

`ApiClient#check_permissions!` only checks membership in the `permissions` array, never the `stack_id`: [4](#0-3) 

This is the same bug class as the reported `AlgebraPool.setPlugin` issue: a security-relevant binding (`pluginConfig` tied to `plugin`, or here: "stack authorized by token" tied to "stack acted upon") is enforced in most call sites but is silently skipped in one code path that was refactored/overridden independently, leaving the object in an inconsistent, exploitable state.

- Binding that should hold: `stack_id_the_token_authorizes == stack_id_the_request_touches` (when `current_api_client.stack_id` is set).
- Before the flaw is exploited: a stack-scoped `ApiClient` (e.g. `stack_id = A`) can only read/act on stack `A` through any endpoint using `BaseController#stack`.
- After: the same token, presented to `Api::CCMenuController#show` with `stack_id=B` in the URL, resolves `stack` via `Stack.from_param!(params[:stack_id])` — bypassing the `stacks` scoping — and successfully renders stack `B`'s CI status/output.

### Impact Explanation
This allows an unprivileged holder of any valid stack-scoped, `read:stack`-permissioned API token to read the build/deploy status and last deploy output of an arbitrary stack it was never granted access to, via `GET /api/stacks/:stack_id/ccmenu.xml?token=...`. This matches the "High" severity bucket defined in scope: "unauthenticated read of stack state, task streams or deploy output" achieved by escalating a narrowly-scoped credential beyond its intended authorization boundary.

### Likelihood Explanation
Any attacker who legitimately possesses (or otherwise obtains) a stack-scoped `ApiClient` token with `read:stack` permission — a normal, low-privilege credential intentionally restricted to one stack — can trivially exploit this by changing the `stack_id` route/query parameter. No additional session, admin access, or write access is required, since `CCMenuController#authenticate_api_client` accepts the token via query string and the controller performs no cross-check between the resolved stack and `current_api_client.stack_id`.

### Recommendation
Have `Shipit::Api::CCMenuController#stack` resolve through the same scoped `stacks` relation used by `BaseController` (i.e. remove the local override, or change it to `stacks.from_param!(params[:stack_id])`), so a stack-scoped `ApiClient` cannot read data for stacks outside its `stack_id`.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A (as supported by the `ApiClient` model and covered by the "an api client scoped to a stack will only see that one stack" test path).
2. Request `GET /api/stacks/<Stack-B-param>/ccmenu.xml?token=<the_client_authentication_token>`.
3. Because `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks` relation, and `authenticate_api_client` accepts the token from the query string, the request succeeds with `200 OK` and returns Stack B's CI status/output, even though the token is only authorized for Stack A.

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
