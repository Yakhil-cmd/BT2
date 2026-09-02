I found a concrete authorization scoping bypass in the CCMenu API endpoint that matches the "stack a token authorizes vs stack it touches" binding.### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's deploy state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` resolution method to bypass the per-`ApiClient` stack scoping that every other API endpoint enforces. A token authorized (via its `stack_id` column) to read only one stack can be used, together with an attacker-supplied `stack_id` query parameter, to fetch CI status/deploy metadata for any stack in the Shipit instance.

### Finding Description
The base API controller centralizes stack scoping for every API resource: it restricts the queryable stack set to the ones the current `ApiClient` is authorized for. [1](#0-0) 

`ApiClient` supports an optional `stack_id` binding that is meant to constrain that client to a single stack. [2](#0-1) 

This is exercised by the `here_come_the_walrus` fixture client, scoped only to the `shipit` stack with `read:stack` permission, and tested to make `index` return just that one stack. [3](#0-2) [4](#0-3) 

However, `CCMenuController` (which only requires the `read:stack` permission, not a specific-stack check) redefines `stack` to resolve directly from `Stack.from_param!(params[:stack_id])` instead of going through the scoped `stacks` collection used by `BaseController`: [5](#0-4) 

Every other controller I found (e.g. `StacksController`) resolves via the scoped `stacks.from_param!(...)`, honoring the `ApiClient#stack_id` restriction: [6](#0-5) 

`require_permission :read, :stack` in `CCMenuController` only checks that the `read:stack` string is present in the token's `permissions` list — it performs no per-stack ownership check: [7](#0-6) 

The equality that should hold is:
`stack authorized by ApiClient#stack_id` == `stack whose data is rendered by CCMenuController#show`

Because `CCMenuController#stack` ignores `current_api_client.stack_id` entirely, this equality is broken: any `stack_id` param value resolves to any `Stack` record system‑wide, regardless of the token's scoping.

### Impact Explanation
An attacker who obtains (or is legitimately issued) a narrowly-scoped `ApiClient` token — e.g. via the `ccmenu_url` feature which creates single-stack, `read:stack`-only tokens (`CCMenuUrlController`) — can query `GET /api/stacks/:any_other_stack_id/ccmenu.xml?token=<their_token>` and receive that other stack's latest deploy/rollback status, activity, last build label, and last build time, none of which the token was authorized to see. This is a cross-stack information-disclosure/authorization-scope escalation: a credential explicitly scoped to one stack reads state belonging to arbitrary other stacks (`read of stack state` a token was not authorized for), matching the High-severity class of unauthorized reads of stack state via a token whose intended scope did not cover it.

### Likelihood Explanation
Likelihood is High for any deployment that issues stack-scoped `ApiClient` tokens (the engine explicitly supports and documents this via `belongs_to :stack, optional: true` and the `ccmenu_url` "single stack, read-only" token flow). No privileged access beyond possessing one such (intentionally narrow) token is required, and the `stack_id` route/query parameter is fully attacker-controlled; there is no additional check tying the resolved `Stack` back to `current_api_client.stack_id`.

### Recommendation
In `CCMenuController#stack`, resolve the stack through the same scoped `stacks` collection used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped tokens cannot be used to read data for stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or use the existing `ccmenu_url` flow) an `ApiClient` scoped to `stack_id = A` with `permissions: ['read:stack']` (mirrors fixture `here_come_the_walrus`).
2. As this client, request `GET /api/stacks/B/ccmenu.xml?token=<token>` where `B` is a different stack the client was never granted access to.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully; `require_permission :read, :stack` passes because the token has `read:stack` in its permission list.
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (bypassing `current_api_client.stack_id` scoping) and returns stack `B`'s record.
5. The response renders stack `B`'s `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` — data the token was never authorized to view — confirming the cross-stack read.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L86-89)
```ruby

      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```
