### Title
Stack-scoped API token can read CCMenu deploy status of any stack, bypassing its `stack_id` authorization scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` enforces per-token stack scoping by filtering the `stacks` relation to `current_api_client.stack_id` before resolving `params[:stack_id]`. `Shipit::Api::CCMenuController` overrides the `stack` accessor to resolve directly from `Stack.from_param!(params[:stack_id])`, skipping the scoped `stacks` collection entirely. Any `ApiClient` with the generic `read:stack` permission — regardless of the specific `stack_id` it was issued for — can therefore fetch CCMenu status for an arbitrary stack it was never authorized to touch.

### Finding Description
`ApiClient` records can optionally be bound to a single `stack` (`belongs_to :stack, optional: true`) [1](#0-0) . The intended authorization binding is: *"the set of stacks a token is entitled to touch equals `stack_id.present? ? {stack_id} : all stacks`"*. This is implemented once, centrally, in `BaseController`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains the string `"read:stack"` — it never checks which stack is being requested [3](#0-2) . The actual enforcement that a stack-scoped client can only see *its own* stack is entirely delegated to the `stacks`/`stack` scoping helper above (confirmed by the test `"an api client scoped to a stack will only see that one stack"` [4](#0-3) ).

`CCMenuController`, however, redefines `stack` to bypass this scoping:

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack

  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end
end
``` [5](#0-4) 

This is the exact analog of `createAgentWithNFT` bypassing the whitelist check performed by `createAgentWithWhitelistUsers`: the protocol-level rule ("stacks a token authorizes == stacks it touches") is implemented in one code path (`BaseController#stack`) but a second, alternate code path to the same class of resource (`CCMenuController#stack`) reimplements the resolution without the restriction, defeating the intended per-stack authorization.

Any caller holding a valid `ApiClient` token with `read:stack` permission — even one explicitly scoped to a single stack such as the `here_come_the_walrus` fixture (`stack: shipit`) [6](#0-5)  — can call `GET /api/stacks/:stack_id/ccmenu.xml` with any other stack's `stack_id` and receive that stack's deploy status (`lastBuildStatus`, `lastBuildLabel`, activity, webUrl, etc.) [7](#0-6) , even though `require_permission :read, :stack` was satisfied only for the client's own permission list, not for that specific stack.

### Impact Explanation
This is an unauthenticated (with respect to the target stack) read of stack state / deploy output through a token that was never granted access to that stack — matching the "High: unauthenticated read of stack state, task streams, or deploy output" impact category. It leaks cross-stack deploy status/activity information (which can include repository/environment/branch identifiers and build outcome) to holders of narrowly-scoped tokens, breaking the trust boundary that stack-scoped API tokens are supposed to enforce (`ApiClient#stack_id`).

### Likelihood Explanation
Any consumer possessing a legitimately-issued, stack-scoped `ApiClient` token with `read:stack` permission (a routine, low-privilege credential intentionally restricted to one stack) can trigger this by simply changing the `stack_id` path/query parameter on the CCMenu endpoint — no additional secret, session, or elevated privilege is required beyond the token itself, and `CCMenuController` even allows the token to be passed as a `token` query-string parameter [8](#0-7) , making exploitation trivial.

### Recommendation
Remove the `stack` override in `CCMenuController` (or reimplement it using the inherited `stacks` scope, i.e. `stacks.from_param!(params[:stack_id])`) so that stack-scoped tokens are restricted to their authorized stack consistently across all API controllers, matching the enforcement already present in `BaseController`/`StacksController`.

### Proof of Concept
1. Using the fixtures, obtain the `authentication_token` for `here_come_the_walrus`, an `ApiClient` scoped to `stack: shipit` with `permissions: [read:stack]` [6](#0-5) .
2. Call `GET /api/stacks/<some-other-stack>/ccmenu.xml?token=<here_come_the_walrus token>` (or via Basic Auth header, as done in `authenticate!` helper) for a stack this client was never assigned to, e.g. `shipit_repositories(:soc)`'s stack.
3. Observe that the request succeeds and returns that other stack's `Project` XML (name, `lastBuildStatus`, `lastBuildLabel`, etc.), whereas the equivalent `Api::StacksController#index`/`#show` request with the same token correctly returns nothing or 404 for stacks outside its scope, per the scoping test `"an api client scoped to a stack will only see that one stack"` [4](#0-3) .

### Citations

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-31)
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
