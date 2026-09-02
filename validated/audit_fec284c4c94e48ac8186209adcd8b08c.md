### Title
Stack-scoped API client can read CCMenu status of any stack, bypassing its authorized stack scope - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` records can be restricted to a single `Stack` via the `belongs_to :stack, optional: true` association [1](#0-0) . `Api::BaseController` enforces this restriction by scoping the `stack` lookup through `stacks`, which filters by `current_api_client.stack_id` when the client is scoped [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to look the record up directly by `params[:stack_id]` without going through the `stacks` scope, so any stack-scoped token can be used to fetch build/deploy status for a stack it was never authorized to access.

### Finding Description
The binding that should hold is: *the stack a token authorizes* (`current_api_client.stack_id`) *== the stack it touches* (`params[:stack_id]` resolved to an actual `Stack`).

`Api::BaseController#stack` maintains this binding:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`Api::CCMenuController` redefines `stack` to bypass this scope entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`require_permission :read, :stack` only checks that the client's `permissions` array contains `"read:stack"` [4](#0-3)  — it never checks that the requested `stack` matches `current_api_client.stack_id`. Because `CCMenuController#show` calls the overridden `stack` method (not the base-class scoped one), the stack-scope restriction that `Api::BaseController` is designed to enforce (and that is explicitly exercised in tests, e.g. "an api client scoped to a stack will only see that one stack" [5](#0-4) ) is silently dropped for this one controller.

This mirrors the `HybridPool` bug class: a value that is supposed to gate an operation (the pool's tracked reserve / here, the client's authorized stack) is bypassed by a code path that reads the "live" unguarded value (`bento.toAmount` / here, `Stack.from_param!(params[:stack_id])`) instead of the value that was actually verified.

### Impact Explanation
An attacker holding a legitimately-issued, stack-scoped API client token (`read:stack` permission, scoped to Stack A) can query `GET /api/stacks/:stack_id/ccmenu` for any other stack B by substituting `stack_id`, and read that stack's deploy/build status output (`stack.deploys_and_rollbacks.last`, rendered via the CCMenu XML view). This is an unauthenticated-for-that-resource read of stack state that the token was never granted — matching the "unauthenticated read of stack state" High-impact category, achieved purely by an unprivileged/limited token crossing its authorization boundary, with no GitHub credentials, session, or additional privilege needed.

### Likelihood Explanation
Exploitation only requires possession of any valid, stack-scoped API client token (a normal, supported low-privilege credential) and knowledge/guessing of another stack's `owner/repo/branch` identifier, which is often public or discoverable. No race condition, timing, or complex setup is required — a single crafted request suffices, making this straightforward to exploit once a scoped token is obtained.

### Recommendation
Remove the `stack` override in `Api::CCMenuController`, or reimplement it to reuse the scoped `stacks` relation from `Api::BaseController` (e.g. `stacks.from_param!(params[:stack_id])`) so stack-scoped tokens cannot resolve stacks outside their authorized scope.

### Proof of Concept
1. An administrator issues an `ApiClient` scoped to Stack A (`stack_id` set, permission `read:stack`).
2. Using that client's Basic Auth token, send `GET /api/stacks/<owner>/<repoB>/<branchB>/ccmenu` where `repoB/branchB` belongs to a different Stack B that the token was never scoped to.
3. `CCMenuController#authenticate_api_client` accepts the token via `ApiClient.authenticate`, and `require_permission :read, :stack` passes because the client's `permissions` includes `read:stack` (the check never inspects `stack_id`).
4. `CCMenuController#show` calls the overridden `stack` method, `Stack.from_param!(params[:stack_id])`, which resolves Stack B directly, ignoring the client's `stack_id` restriction.
5. The response renders Stack B's latest deploy/rollback status — data the Stack-A-scoped token should never have been able to read.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
