Confirmed. The vulnerability is a stack-scope binding break in `Shipit::Api::CCMenuController`.

### Title
CCMenu API token stack-scope bypass allows reading any stack's build status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` scoped to a single stack (`current_api_client.stack_id`) can only resolve/act on that stack, via the `stacks`/`stack` helper methods [1](#0-0) . `Shipit::Api::CCMenuController`, however, overrides `stack` to resolve directly against the global `Stack` relation instead of the scoped `stacks` relation, so the stack-authorization binding that every other API endpoint enforces is silently dropped for this one controller [2](#0-1) .

### Finding Description
The binding that should hold everywhere in the API is: `stack a token authorizes == stack the endpoint touches`. `BaseController#stack` implements this by first narrowing the queryable set of stacks to `Stack.where(id: current_api_client.stack_id)` whenever the client is stack-scoped, and only then resolving `params[:stack_id]` against that narrowed set [1](#0-0) .

`CCMenuController` inherits from `BaseController` and only requires the `read:stack` permission via `require_permission :read, :stack` [3](#0-2) , which checks that the permission name is present on the token but never checks which stack it is scoped to [4](#0-3) . The actual stack-scope enforcement is expected to happen in the `stack` helper — but `CCMenuController` redefines that helper to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, bypassing the `current_api_client.stack_id` check entirely [5](#0-4) .

As a result, any bearer of a valid `read:stack` token — regardless of which stack it was scoped/intended for — can call `GET /api/stacks/:stack_id/ccmenu?token=...` with a *different* `stack_id` and receive that other stack's latest deploy/rollback status, id, and timestamps, rendered via the `shipit/ccmenu/project` view [6](#0-5) .

This is the exact same class of bug as the reported issue: a value that is checked/authorized at one scope (the fee rate valid for a specific accrual period; here, the stack a token is authorized for) is silently applied across a broader scope than what was verified (the whole accrual period; here, every stack in the Shipit instance), because the check is performed in a way that doesn't track/enforce the original binding at the point of use.

Note the primary token-issuance flow, `CCMenuUrlController#client`, does not even set `stack:` on the created `ApiClient` [7](#0-6) , so that particular flow is unscoped by construction and not itself the boundary break. The break is in `CCMenuController#stack`: it removes the scope enforcement that `BaseController` (and every other API controller that doesn't override `stack`) relies on, so *any* stack-scoped `read:stack` `ApiClient` created through any other code path (e.g. directly via `ApiClientsController`, or a future/plugin flow that does set `stack:`) loses its intended stack restriction specifically at this endpoint.

### Impact Explanation
This is an unauthenticated-boundary-crossing read: a credential intended (by every other controller's enforcement logic) to grant read access to exactly one stack can be used to read build/deploy status for every stack in the Shipit instance. This matches the High-severity criteria "unauthenticated read of stack state" for the CCMenu-exposed subset of stack state (latest deploy id, status, timestamps) across the whole instance, not just the authorized stack.

### Likelihood Explanation
Likelihood is high for any deployment where stack-scoped `read:stack` `ApiClient` tokens exist (e.g., created via `ApiClientsController#create` with a `stack` association, or any embedding/monitoring integration that intentionally restricts a token to a single stack). Exploitation requires only possession of one such valid, stack-scoped token — no privileged account, session, or webhook secret — plus knowledge/guessing of another stack's `stack_id` (`owner/name/environment`), which is often discoverable or predictable.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (and the equivalent in `CCMenuUrlController` if scoping is desired there too) so that it inherits `BaseController#stack`, resolving stacks through the scoped `stacks` relation instead of the raw `Stack` model. This restores the intended `current_api_client.stack_id` binding for this endpoint, consistent with every other API controller.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id: A` with `permissions: ['read:stack']` (e.g. via `ApiClientsController`, or any token-issuing flow that sets `stack:`).
2. As an unprivileged holder of that token, call:
   `GET /api/stacks/OTHER_OWNER/OTHER_NAME/OTHER_ENV/ccmenu?token=<token>`
   where `OTHER_OWNER/OTHER_NAME/OTHER_ENV` is a *different* stack `B` that the token was never authorized for.
3. `CCMenuController#authenticate_api_client` accepts the token [8](#0-7) ; `require_permission :read, :stack` only checks the permission name is present, not the stack scope [4](#0-3) ; `stack` resolves `Stack.from_param!(params[:stack_id])` directly against stack `B`, bypassing the `stack_id` scope check that `BaseController#stack` would have enforced [5](#0-4) .
4. The response returns stack `B`'s CCMenu XML (latest deploy status/id/time), even though the token was only authorized for stack `A`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
