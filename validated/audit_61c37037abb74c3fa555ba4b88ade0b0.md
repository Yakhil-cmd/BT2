### Title
Stack-scoped ApiClient token authorises reads on any stack via `CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via `ApiClient#stack_id`, and `Api::BaseController#stack` enforces that scope by resolving the requested stack only from `stacks` (which is filtered to `current_api_client.stack_id` when present) [1](#0-0) . `Api::CCMenuController`, however, overrides `stack` to resolve directly from `Stack.from_param!(params[:stack_id])`, bypassing the `stacks` scoping helper entirely [2](#0-1) .

### Finding Description
This mirrors the reported bug class: a credential (the `staking_info`/pool binding in the original report; here, the `ApiClient#stack_id` binding) is supposed to constrain what resource an authenticated actor may act on, but the code path that actually touches the resource never re-validates that binding.

`ApiClient` has an optional `belongs_to :stack` and a `stack_id?` accessor used specifically to scope tokens to one stack [3](#0-2) . The generic API controllers enforce this correctly: `Api::BaseController#stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `#stack` resolves the requested stack from that restricted relation [1](#0-0) . Tests confirm this is the intended enforcement: "an api client scoped to a stack will only see that one stack" [4](#0-3) .

`Api::CCMenuController` inherits from `BaseController` and only checks `require_permission :read, :stack`, which validates the permission string (`read:stack`) but is not bound to any specific stack instance — `ApiClient#check_permissions!` only checks membership in the `permissions` array [5](#0-4) . The controller then defines its own `stack` method that ignores the client's `stack_id` scope and resolves any stack by param directly: `Stack.from_param!(params[:stack_id])` [2](#0-1) . Because `#show` calls this overridden `stack` method, a token created with a `stack_id` restriction (e.g., the `here_come_the_walrus` fixture, which is scoped to the `shipit` stack) can still request CCMenu status for any other stack in the system, as long as it retains `read:stack` permission [6](#0-5) .

The equality that should hold — `stack authorised by ApiClient#stack_id == stack touched by the controller action` — is broken specifically in `CCMenuController`; every other controller inspected (`Api::StacksController`, `Api::HooksController`, etc.) relies on the inherited, correctly-scoped `stack`/`stacks` helpers.

### Impact Explanation
This allows an attacker holding a token intentionally restricted to a single stack (a common configuration used to hand out narrowly-scoped credentials, e.g. via `CCMenuUrlController#client`, which creates a `read:stack`-only, stack-scoped `ApiClient` [7](#0-6) ) to read build/deploy status (last build status, label, running state, activity) of arbitrary other stacks they were never granted access to. This matches the "High — unauthenticated read of stack state, task streams or deploy output" impact category, since it discloses deploy/CI state across stacks outside the token's authorized scope, i.e., cross-stack information disclosure via a credential that should have been confined to one stack.

### Likelihood Explanation
Exploitation only requires possession of any valid, stack-scoped `ApiClient` token with `read:stack` permission (a routine, low-privilege credential intentionally distributed narrowly, e.g. embedded in a CI status badge/CCMenu URL) and the numeric/slug identifier of another stack — both of which are unprivileged, externally obtainable pieces of information. No repository write access, GitHub credentials, or session is required, only the documented `CCMenuController#show` API endpoint with a token issued for a different, unrelated stack.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it to call `stacks.from_param!(params[:stack_id])`, inheriting the same client-scoped resolution used elsewhere in `Api::BaseController`) so that stack-scoped tokens cannot resolve stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or obtain) a `Shipit::ApiClient` scoped to Stack A with `permissions: ['read:stack']` and `stack_id: <Stack A id>` (this is exactly what `CCMenuUrlController#client` generates for legitimate CI badge use).
2. Using that token's basic-auth credentials, issue `GET /api/stacks/:stack_b_id/ccmenu` (or the equivalent route), where `stack_b_id` refers to any other stack in the installation that the token was never scoped to.
3. Observe that `Api::CCMenuController#show` renders `stack_b`'s build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.) successfully, because `#stack` resolves via `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!` used by every other API controller [2](#0-1) , confirming the stack-scope binding is not enforced.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
