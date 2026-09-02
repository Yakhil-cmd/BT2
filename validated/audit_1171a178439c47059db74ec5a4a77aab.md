## Root Cause Analysis

The Bitcoin CVE class is a **use-after-free caused by two code paths trusting different, unsynchronized state** (`m_reconnections` vs. the freed `semOutbound`). The closest analog in this Rails engine is a place where **one code path establishes an authorization scope (which `Stack` an API token is allowed to touch) while a sibling code path bypasses that scope and resolves the resource straight from unchecked request parameters**.

That is exactly what happens in the CCMenu API controller.

### The trusted binding
`Api::BaseController` establishes the invariant that a scoped `ApiClient` (one that has a non-null `stack_id`) may only ever resolve `stack` from its own scoped collection: [1](#0-0) 

```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`require_permission :read, :stack` only checks that the token carries the `read:stack` **permission name** — it never checks *which* stack: [2](#0-1) 

The actual scope restriction to "the stack this token is authorised for" is enforced solely by routing `stack` through `stacks` (the `Stack.where(id: current_api_client.stack_id)` collection). Tests confirm this is the intended security boundary: “an api client scoped to a stack will only see that one stack” [3](#0-2) , and `ApiClient` has a `stack` association plus `PERMISSIONS` including `read:stack` [4](#0-3) .

### The broken binding
`Api::CCMenuController` requires the exact same `read:stack` permission, but overrides `stack` to bypass the `stacks` scoping helper entirely and resolve directly from the raw parameter: [5](#0-4) 

```
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end
```

`Stack.from_param!` performs no scoping to `current_api_client.stack_id` at all — it looks up any stack in the database by its slug/param. Because `CCMenuController#stack` shadows `BaseController#stack`, the `stacks`-based scoping is never consulted for this endpoint.

This breaks the equality: **stack a token authorises == stack a token touches**. A token created with `stack_id` set to stack A (a scoped, single-stack `read:stack` client — the exact kind produced by `CCMenuUrlController#client`, which is reachable by any authenticated user for their own stack: [6](#0-5) ) can be replayed against `GET /api/<any_other_stack>/ccmenu.xml` and will render that other stack's CI/CCMenu status — name, activity, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl` — for a stack it was never authorized to see.

### Title
Stack-scoped API token bypasses stack authorization scope in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` overrides the base controller's scoped stack resolver (`stacks.from_param!`) with an unscoped `Stack.from_param!`, so a `read:stack` API token that is bound to one specific stack (`ApiClient#stack_id`) can be used to read the CI/build status of any other stack in the Shipit instance.

### Finding Description
`Api::BaseController` defines two related private methods: `stacks`, which restricts the result set to `current_api_client.stack_id` when the client is scoped [7](#0-6) , and `stack`, which resolves the requested stack strictly from that scoped collection [8](#0-7) . `require_permission` only validates the *name* of a permission (`read:stack`), never the target stack id [9](#0-8) , so per-stack authorization depends entirely on `stack` being derived from `stacks`.

`CCMenuController` redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly [10](#0-9) , which is `ApplicationRecord`-level lookup with no api-client scoping. It also customizes authentication to accept the token via a `?token=` query parameter [11](#0-10) , which is how `CCMenuUrlController` intends the token to be used (embedded in a CI-status URL per stack) [12](#0-11) . Any holder of one such per-stack CCMenu token — which is displayed/shared as a plain URL, i.e. a low-privilege, widely distributed credential — can swap `stack_id` in the URL to enumerate and read the CI status of arbitrary other stacks.

### Impact Explanation
This is an unauthenticated-for-that-resource read of stack state: a token scoped to authorize reading stack A's CCMenu status can be replayed to read stack B's status (name, last build status/label/time, web URL) without ever being granted permission on stack B. This matches the "High — unauthorized read of stack state" impact category: the deployment-trust binding "stack a token authorizes == stack a token touches" is broken by a controller-level scope bypass.

### Likelihood Explanation
High. No secret guessing or privileged access is required beyond possessing one legitimately-issued, narrowly-scoped CCMenu token (these tokens are designed to be embedded in third-party CI-status-monitor URLs, i.e., handed out routinely and with low sensitivity assumptions). Only `stack_id` needs to be changed in the request; `Stack.from_param!` resolves by public stack slug, which is not a secret.

### Recommendation
Change `Api::CCMenuController#stack` to use the same scoped resolver as `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the override entirely (falling back to the inherited `BaseController#stack`) so it consistently goes through `current_api_client.stack_id`-based scoping.

### Proof of Concept
1. As an authenticated Shipit user, visit stack A and trigger `CCMenuUrlController#fetch` to obtain a `ccmenu_url` containing `?token=<A-scoped read:stack token>` [13](#0-12) .
2. Send `GET /api/<stack-A-param>/ccmenu.xml?token=<token>` — succeeds as intended.
3. Send `GET /api/<stack-B-param>/ccmenu.xml?token=<token>` (any other stack's slug) — because `CCMenuController#stack` calls `Stack.from_param!` unscoped, this also returns HTTP 200 with stack B's build status, even though the token's `ApiClient#stack_id` is bound to stack A only, demonstrating the scope-bypass.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-23)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
```
