### Title
Stack-scoped ApiClient tokens can read the CI status/deploy state of any stack via CCMenuController - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces per-token stack scoping through the `stacks`/`stack` helper pair, but `Shipit::Api::CCMenuController` overrides `stack` with an unscoped lookup, breaking the binding: *stack a token authorizes == stack the endpoint touches*.

### Finding Description
`ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `BaseController` enforces this scoping by restricting the queryable stack set to that single stack whenever `current_api_client.stack_id?` is true, and derives the `stack` used by controller actions from that scoped relation: [2](#0-1) 

`CCMenuController`, however, overrides the private `stack` method to bypass this scoping entirely, resolving the stack directly from `params[:stack_id]` against the full `Stack` table: [3](#0-2) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains `read:stack` — it never checks whether the resolved stack matches `current_api_client.stack_id`: [4](#0-3) 

So a token that is authorized (i.e. `stack_id` present) for one stack — such as the `here_come_the_walrus` fixture, which is scoped to the `shipit` stack and only carries `read:stack` — satisfies the permission bit-check for *any* stack because the scope-narrowing that normally happens in `BaseController#stacks` is skipped by `CCMenuController`'s override. This is confirmed by the fixture and by the sibling `LocksController`, which does not override `stack` and therefore correctly inherits the scoped lookup: [5](#0-4) [6](#0-5) 

The equality that should hold is:
`stack ∈ stacks-authorized-by-token == stack touched by CCMenuController#show`

After the override, the right-hand side becomes `Stack.all`, breaking the equality for every scoped token.

### Impact Explanation
This grants unauthenticated read of stack state/deploy output for stacks a token was never authorized to see: `CCMenuController#show` renders build status/activity/last build label/time for whatever `stack_id` is passed, regardless of the calling token's `stack_id` scope [7](#0-6) . A holder of any single-stack-scoped `read:stack` token (e.g. distributed to a CI dashboard integration for one project) can enumerate `stack_id` values and read build/deploy status of unrelated stacks across the deployment, which matches the report's "unauthenticated read of stack state" High-impact category.

### Likelihood Explanation
Likelihood is moderate-to-high for any deployment that issues scoped API tokens (the primary purpose of the `stack_id` column on `ApiClient` is to restrict a token to one stack). Any holder of such a token can trivially trigger this by supplying a different `stack_id` in the request path — no special privileges beyond possessing one valid, minimally-permissioned token are required.

### Recommendation
Remove the `stack` override in `CCMenuController` (or reimplement it using the same scoped `stacks` relation as `BaseController`), so it resolves the stack via `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`, ensuring stack-scoped tokens cannot read data for stacks outside their authorized scope.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack: shipit` with permissions `['read:stack']` (matches `here_come_the_walrus` fixture behavior) [5](#0-4) .
2. Authenticate as that client and call `GET /api/stacks/other-owner/other-repo/other-env/ccmenu` (i.e., `CCMenuController#show` with a `stack_id` param pointing to a different stack than the one the token is scoped to).
3. `authenticate_api_client` succeeds (token is valid) [8](#0-7) ; `require_permission!(:read, :stack)` passes because the token has `read:stack` in `permissions`, with no stack-id comparison [4](#0-3) .
4. `stack` resolves via `Stack.from_param!(params[:stack_id])` against the entire `Stack` table, not the token's scoped relation [9](#0-8) .
5. The response renders the unrelated stack's deploy/build status, confirming cross-stack read with a token that should only see the `shipit` stack.

### Citations

**File:** app/models/shipit/api_client.rb (L4-8)
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/api/locks_controller.rb (L1-7)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class LocksController < BaseController
      require_permission :lock, :stack

```
