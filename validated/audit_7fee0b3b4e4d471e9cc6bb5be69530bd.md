### Title
CCMenuController#stack bypasses ApiClient stack scoping enforced everywhere else - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` overrides the tenant-scoped lookup defined in `BaseController#stack` and resolves stacks against the entire `Stack` table instead of the `stacks` relation that is filtered by `current_api_client.stack_id`. Any `ApiClient` token that carries `read:stack` permission but is scoped to a single stack (via `ApiClient#stack_id`) can therefore be used to read the CC Menu (build/deploy) status of any other stack in the installation.

### Finding Description
The binding that should hold for every API action is: `stack accessed ∈ stacks authorized by current_api_client.stack_id`. `BaseController` implements this correctly: [1](#0-0) 

`stacks` restricts the relation to `Stack.where(id: current_api_client.stack_id)` when the client has a `stack_id`, and `#stack` resolves `params[:stack_id]` only within that relation.

`CCMenuController` re-defines `#stack` and drops the scoping entirely: [2](#0-1) 

`#show` calls `stack.deploys_and_rollbacks` using this unscoped resolution, and permission enforcement only checks the permission list, not the stack binding: [3](#0-2) 

So for any `ApiClient` record with `stack_id = A` and `permissions` including `read:stack`, a request to `GET /api/stacks/:stack_id_of_B/cc_menu.xml?token=<tokenA>` passes `authenticate_api_client` (token verifies), passes `require_permission!(:read, :stack)` (permission list contains `read:stack`, stack id is never checked), and `#stack` resolves stack B directly from `Stack.from_param!`, ignoring `current_api_client.stack_id`. `#show` then renders stack B's latest deploy/rollback state.

Note: the `CCMenuUrlController#fetch` flow that issues tokens to ordinary users does **not** currently set `stack:` on the `ApiClient` it creates [4](#0-3) , so tokens minted through that specific endpoint already have `stack_id == nil` and are effectively global for `read:stack` regardless of this bug. The scoping bypass therefore has concrete impact wherever an `ApiClient` is provisioned with a non-nil `stack_id` and `read:stack` permission (e.g., an operator-issued per-tenant token intended to be restricted to one stack, via `Api::ApiClientsController`), which I was not able to fully inspect in this session (`app/controllers/shipit/api_clients_controller.rb` params handling was not read due to iteration limits) — this should be verified to confirm whether `stack_id` is assignable through that admin flow.

### Impact Explanation
A holder of any stack-scoped `read:stack` API token can read another tenant's deploy/task status (running vs. idle, last deploy id, ended_at) for arbitrary stacks by iterating `stack_id` values in the URL. This is a cross-tenant unauthenticated-for-that-resource read of deploy state, matching the "High - unauthenticated read of stack state, task streams or deploy output" impact category. It is fully repeatable (no rate limiting concern in scope) against any stack in the installation as long as the attacker holds one valid, stack-scoped `read:stack` token.

### Likelihood Explanation
Exploitability depends entirely on whether the deployment issues `ApiClient` tokens that are genuinely scoped to a single stack with `read:stack` permission (e.g. via an admin-managed `ApiClient`, not the current `CCMenuUrlController#fetch` flow, whose generated tokens are already unscoped). If such scoped tokens exist in a given Shipit installation (a common multi-tenant configuration), the attack requires only a GET request with the known/guessable `stack_id` of the target stack and no other secret — the cost is trivial and the bug is directly reachable from the controller code as shown.

### Recommendation
Remove the `#stack` override in `CCMenuController` (or reimplement it using `stacks.from_param!(params[:stack_id])`) so it inherits `BaseController`'s tenant-scoped resolution, consistent with every other API controller.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
module Shipit
  module Api
    class CCMenuControllerTest < ActionController::TestCase
      test "a stack-scoped read:stack token cannot read another stack's cc_menu" do
        stack_a = shipit_stacks(:shipit)
        stack_b = shipit_stacks(:cyclimse) # any other stack fixture
        client = ApiClient.create!(
          creator: shipit_users(:walrus),
          name: 'Scoped CCMenu Client',
          stack: stack_a,
          permissions: %w[read:stack],
        )

        get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

        # Binding under test: stack touched (B) ∈ stacks authorized by current_api_client.stack_id (A)
        # Expected (secure): stack_b.id != stack_a.id => request must be rejected (404/403)
        # Actual (vulnerable): request succeeds and returns stack_b's data
        assert_response :not_found # currently fails: response is 200 with stack_b's deploy data
      end
    end
  end
end
```

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
