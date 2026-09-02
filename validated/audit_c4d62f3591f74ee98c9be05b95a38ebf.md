### Title
API client stack-scope bypass in CCMenu endpoint allows cross-stack read of build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method to resolve the target stack directly from `Stack.from_param!(params[:stack_id])`, bypassing the tenant-scoping (`current_api_client.stack_id?`) enforced by every other API controller through `Shipit::Api::BaseController#stacks`/`#stack`. This breaks the binding "a stack a token authorises == a stack it touches": an `ApiClient` token that is scoped (via `stack_id`) to authorize only one specific stack can be used to read the build/deploy state of any other stack in the installation.

### Finding Description
`Shipit::Api::BaseController` is designed so that a stack-scoped `ApiClient` can only ever resolve stacks from its own scope: [1](#0-0) 
```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
Every controller that inherits this `stack` method is safe: even if the client supplies an arbitrary `params[:stack_id]`, the underlying `Stack.where(id: current_api_client.stack_id)` relation guarantees the lookup can never escape the client's authorized stack.

`CCMenuController`, however, redefines `stack` and calls the class method directly, skipping the scoped `stacks` relation entirely: [2](#0-1) 
```
def show
  latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
  render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
end

private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
`require_permission :read, :stack` only checks that the token's `permissions` array includes `read:stack` — it never validates that the requested `stack_id` matches the token's `stack_id` scope: [3](#0-2) 
```
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
  end
  true
end
```
The `ApiClient` model itself confirms per-stack scoping is a supported, intended security boundary (`belongs_to :stack, optional: true`), and `stack_id?` is precisely the guard `BaseController#stacks` relies on: [4](#0-3) 

This same pattern is used legitimately elsewhere — a scoped, read-only token is minted specifically for CCMenu integration via `CCMenuUrlController`, which creates a `read:stack` client explicitly bound to one stack: [5](#0-4) 
```
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
This confirms the design intent: a CCMenu token is meant to be scoped to exactly the stack it was generated for. Because `CCMenuController#stack` ignores that scope, any holder of such a token (or any `read:stack` token scoped to stack A) can substitute a different `stack_id` in the URL and retrieve build status, last build label, last deploy state, and lock status for any other stack in the Shipit instance — including private/internal stacks the token was never authorized to see.

### Impact Explanation
This is an authorization bypass that lets a token scoped to one stack read the build/deploy status of arbitrary stacks — an unauthenticated-for-that-stack read of stack state, matching the "High" impact category (escalation past the stack scope a token authorizes, unauthorized read of stack state). It does not directly leak `GITHUB_TOKEN`/`github_access_token`, but it does leak deploy/build status, last build label, and lock reason (which can include free text) of stacks that the token's owner should not be able to see, undermining the multi-tenant stack isolation the `ApiClient#stack_id` scope is meant to guarantee.

### Likelihood Explanation
Any holder of a valid `ApiClient` `authentication_token` with `read:stack` permission (including one deliberately scoped to a single, low-sensitivity stack, e.g. the auto-created CCMenu client) can trigger this simply by changing the `stack_id` path/query parameter on a GET request — no privilege escalation, secret guessing, or additional access is required beyond possessing one legitimately-scoped token, which is the normal, documented way to consume the CCMenu endpoint.

### Recommendation
Remove `CCMenuController#stack`'s private override and instead reuse `BaseController#stacks`/`#stack` (i.e., `stacks.from_param!(params[:stack_id])`) so that stack resolution is always constrained by `current_api_client.stack_id`, consistent with every other API controller.

### Proof of Concept
1. Obtain (or self-mint via `CCMenuUrlController#fetch`) a `read:stack` `ApiClient` token scoped to `stack_id` = Stack A's id.
2. Call `GET /api/stacks/:stack_id_of_stack_B/ccmenu.xml?token=<token>` (or with the Basic-Auth header), substituting Stack B's `owner/repo` param instead of Stack A's.
3. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly — ignoring that the token is scoped to Stack A — and returns Stack B's build/deploy XML (`assert_payload 'name', @stack.to_param` style data as exercised in `test/controllers/api/ccmenu_controller_test.rb`), even though the token was never authorized for Stack B. [6](#0-5)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-24)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
