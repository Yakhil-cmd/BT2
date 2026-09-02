### Title
Stack-scoped API tokens bypass their stack restriction on the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` binds `stack = permission-checked scope` to the equation `stack ∈ stacks == (current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all)` [1](#0-0) . `Api::CCMenuController` overrides `stack` to `Stack.from_param!(params[:stack_id])`, dropping the `stacks` scoping entirely [2](#0-1) , while `require_permission :read, :stack` still only checks whether the token holds the `read:stack` permission string, not which stack it is scoped to [3](#0-2) . This breaks the binding "stack a token authorizes == stack it touches."

### Finding Description
`ApiClient` records can be scoped to a single stack via `stack_id`, and `permissions` such as `read:stack` are checked purely by string membership with `check_permissions!` [4](#0-3) . In every other API endpoint (`StacksController`, `TasksController`, `DeploysController`, `LocksController`), the target `stack` is resolved through `BaseController#stack`, which is intersected with the token's authorized stack set: `stacks = current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) . This is exactly the scoping the fixtures document: the `here_come_the_walrus` client is bound to the `shipit` stack with only `read:stack` and is asserted to see only that one stack in `StacksController#index` [5](#0-4) .

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

The controller still declares `require_permission :read, :stack` [6](#0-5) , but that check never inspects `current_api_client.stack_id`, only whether `read:stack` is present in `permissions` [3](#0-2) . As a result, any token holding `read:stack` — including ones intentionally scoped to a single stack via `stack_id` — can be replayed against `GET /api/stacks/:stack_id/ccmenu.xml` with an arbitrary `stack_id` belonging to a different stack, and will successfully render that other stack's CCMenu project data.

### Impact Explanation
This is an authorization/scope-escalation bug: a token whose intended authorization surface is a single stack can read the deploy/build state (`lastBuildStatus`, `lastBuildLabel`, activity, lock status, project name) of any stack in the Shipit instance [7](#0-6) . This matches the in-scope High-severity class "unauthenticated read of stack state, task streams or deploy output" via escalation past the intended stack-scoping authorization.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` API token (a normal, low-privilege credential intentionally issued for a single project's CI dashboard integration) can trivially exploit this by changing the `stack_id` in the request URL/query string — no special access or social engineering required, and the CCMenu controller explicitly supports unauthenticated-header token auth via query string (`ApiClient.authenticate(params[:token])`) [8](#0-7) .

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, scoped `stacks.from_param!(params[:stack_id])` from `BaseController`, so a stack-scoped token cannot resolve stacks outside its `current_api_client.stack_id`.

### Proof of Concept
1. Admin issues an `ApiClient` scoped to Stack A only: `permissions: ['read:stack']`, `stack_id: A.id` (as in fixture `here_come_the_walrus`) [5](#0-4) .
2. Using that token's `authentication_token`, request `GET /api/stacks/:stack_id/ccmenu.xml` (per `CCMenuController#show`) with `stack_id` set to Stack B (a stack the token was never granted) [7](#0-6) .
3. `authenticate_api_client` authenticates successfully via `ApiClient.authenticate(params[:token])` [8](#0-7) ; `require_permission :read, :stack` passes because the token has `read:stack` regardless of `stack_id` [3](#0-2) ; `stack` resolves Stack B directly via `Stack.from_param!(params[:stack_id])`, ignoring `current_api_client.stack_id` [2](#0-1) .
4. Response renders Stack B's CCMenu project XML (build status, activity, lock state) despite the token being authorized only for Stack A.

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

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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
