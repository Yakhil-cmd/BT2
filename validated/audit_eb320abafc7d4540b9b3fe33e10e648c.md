Confirmed: `Api::StacksController#stack` correctly scopes through `stacks.from_param!` (where `stacks` filters by `current_api_client.stack_id` when the client is stack-scoped), at [1](#0-0) , backed by the scoping logic in `BaseController#stacks`/`#stack` at [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly against the *global* `Stack` scope, bypassing the `current_api_client.stack_id` restriction entirely, at [3](#0-2) . The `CCMenuUrlController` mints exactly this kind of narrowly-scoped, `read:stack` token bound to one stack and embeds it in a plain, unauthenticated URL meant for CI badges/status widgets, at [4](#0-3) .

### Title
Stack-scoped CCMenu API token authorizes reading any stack's CI status, not just the stack it was issued for - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` records can be scoped to a single `stack` so their token only authorizes actions on that stack [5](#0-4) . This scoping is normally enforced through `BaseController#stacks`, which filters the queryable stacks down to `current_api_client.stack_id` when the client is stack-bound [2](#0-1) . `Api::CCMenuController` opts out of this enforcement by overriding `stack` to resolve directly against the global `Stack` relation using the caller-supplied `params[:stack_id]`, only checking that the token carries the `read:stack` permission bit — never that the bit applies to *this* stack [6](#0-5) .

### Finding Description
The binding that should hold is: **stack a token authorizes == stack a token touches**. Before the attack, a stack-scoped CCMenu token `T` (created by `CCMenuUrlController#client`, `permissions: %w[read:stack]`, `stack: S1`) is only ever placed in URLs meant to display `S1`'s CI status publicly, e.g. `GET /api/stacks/S1/ccmenu?token=T`, at [4](#0-3) .

`CCMenuController` authenticates the request purely from `params[:token]`:
```ruby
def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```
and then resolves the target stack independently of that client:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!(operation, scope)`, which checks the string `"read:stack"` is present in `permissions` — it never compares `stack_id` to the resolved `stack.id` [7](#0-6) .

After the attack: anyone who observes token `T` (embedded in a plaintext CI badge URL, README, or status widget — exactly the kind of low-trust, publicly-displayed credential the feature is designed to expose) can replay it with a different `stack_id`, e.g. `GET /api/stacks/S2/ccmenu?token=T`, and successfully read `S2`'s deploy/build status even though `T.stack_id == S1.id`. This is a capture-replay authentication bypass: a credential minted and trusted for one authorization context (`stack: S1`) is accepted and honored in a different context (`stack: S2`) it was never meant to authorize, purely because the endpoint never re-derives the stack from the token's own scope.

### Impact Explanation
This lets an unprivileged attacker who captures one lightweight, intentionally-shared CCMenu token escalate to unauthenticated read of *any* stack's task/deploy status output (build results, deploy state, timestamps) across the whole Shipit instance — matching the "unauthenticated read of stack state, task streams or deploy output" High-severity criterion, since the leaked token was never meant to grant visibility beyond its own stack.

### Likelihood Explanation
Likely. CCMenu tokens are explicitly designed to be embedded in unauthenticated, shareable URLs (CI status badges, dashboards), so their capture requires no privileged access — just observing a publicly displayed URL. Exploiting the bug is a single unauthenticated `GET` request with a substituted `stack_id`, requiring no further access, tokens, or timing.

### Recommendation
In `Api::CCMenuController#stack`, resolve the stack the same way `BaseController` does for scoped clients — verify `current_api_client.stack_id` (if present) matches the requested stack, e.g. reuse `stacks.from_param!(params[:stack_id])` (scoped by `current_api_client.stack_id?`) instead of calling `Stack.from_param!` against the unscoped relation.

### Proof of Concept
1. As an authenticated Shipit user, visit `GET /ccmenu/S1` (`CCMenuUrlController#fetch`) to mint/obtain a `read:stack` token scoped to stack `S1`; the returned `ccmenu_url` contains `?token=T`.
2. Note that `T` is designed to be embedded unauthenticated in a CI badge/README, i.e. is exposed outside of any privileged session.
3. As an unauthenticated party who has observed `T`, request `GET /api/stacks/S2/ccmenu?token=T` for an unrelated stack `S2`.
4. The request succeeds (`ApiClient.authenticate(T)` succeeds, `check_permissions!(:read, :stack)` passes because `T` has `read:stack`), and `Stack.from_param!(params[:stack_id])` resolves `S2` regardless of `T.stack_id == S1.id`, returning `S2`'s CI status — demonstrating the token is replayable across stacks outside its authorized scope.

### Citations

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
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
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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
