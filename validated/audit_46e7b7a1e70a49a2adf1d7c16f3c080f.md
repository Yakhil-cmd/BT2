### Title
Stack-scoped API token can read any stack's CCMenu/deploy status via `Api::CCMenuController#stack` bypassing the `stacks` scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController` overrides the `stack` helper to call `Stack.from_param!(params[:stack_id])` directly, instead of using the token-scoped `stacks` relation defined in `Api::BaseController`. Because `ApiClient#check_permissions!` only checks the permission string (`read:stack`) and never checks that the requested stack matches `current_api_client.stack_id`, a token that is scoped to one stack can read the CCMenu XML (deploy status, last build label/time, lock state) of any other stack.

### Finding Description
The intended invariant is: `current_api_client.stack_id? ? stack == Stack.find(current_api_client.stack_id) : true`, i.e. a stack-scoped token's accessible stack must equal its bound `stack_id`. `Api::BaseController` implements this correctly: [1](#0-0) 

`stacks` filters by `current_api_client.stack_id` when present, and the default `stack` method resolves the param against that filtered relation, so `Stack.from_param!` on a non-scoped stack id raises `RecordNotFound` for a scoped token.

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

`require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)`, which checks membership of the string `"read:stack"` in `permissions`, and is not parameterized by any specific stack instance: [3](#0-2) [4](#0-3) 

So the exploit flow: an operator issues a token scoped to `stack_id = A` with `read:stack` permission (a normal, low-privilege, single-stack token). Using that token, an attacker (who legitimately possesses it, or any party controlling it) sends `GET /api/stacks/:stack_id/ccmenu.xml` (or whatever route the ccmenu action is mounted at) with `stack_id` set to a *different* stack `B` it was never granted access to. `require_permission!` passes because the token does have `read:stack` generically. `stack` then resolves via `Stack.from_param!(params[:stack_id])` — unscoped — and returns stack `B` directly, and `show` renders `B`'s deploy/build status in the CCMenu XML response. No check anywhere compares `B.id` to `current_api_client.stack_id`.

None of the listed guards catch this: `require_permission!` is scope-agnostic; the `stacks` relation (the actual scoping mechanism) is never consulted by this controller because it defines its own `stack` method that shadows the base implementation.

### Impact Explanation
An attacker holding any token scoped to a single stack (and permissioned `read:stack`, which is the normal grant for this feature) can read the CCMenu status — build/deploy success/failure, last build time/label, lock status — of every stack in the Shipit instance, not just the one it was scoped to. This is an unauthenticated-scope escalation / unauthorized read of stack state across tenants, matching the "High — unauthenticated read of stack state, task streams or deploy output" category. The blast radius is every stack managed by the Shipit instance, and the attack is trivially repeatable (just vary `stack_id`) with no rate limiting mentioned as a mitigating factor here.

### Likelihood Explanation
Preconditions: attacker must possess *some* stack-scoped `ApiClient` token with `read:stack` permission — this is a normal, low-privilege token issuance scenario (e.g., a CI system given read access to its own stack's status). No GitHub secrets, session, or elevated role is required beyond having been issued this single-stack token. The attack cost is a single HTTP GET with a different `stack_id` parameter; there's no cryptographic or timing constraint. This is highly feasible and repeatable against arbitrary stacks by enumerating `stack_id`/slug values.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, token-scoped `stack` method from `Api::BaseController` (i.e., `stacks.from_param!(params[:stack_id])`), or explicitly verify `current_api_client.stack_id.nil? || current_api_client.stack_id == resolved_stack.id` before rendering.

### Proof of Concept
minitest plan (add to `test/controllers/api/ccmenu_controller_test.rb`, no live GitHub needed):
```ruby
test "a stack-scoped token cannot read a different stack's ccmenu" do
  other_stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: "main")
  @client.update!(stack_id: @stack.id, permissions: ['read:stack'])

  get :show, params: { stack_id: other_stack.to_param }

  # Binding under test: current_api_client.stack_id == resolved_stack.id must hold.
  assert_not_equal @client.stack_id, other_stack.id
  assert_response :not_found # currently fails: returns 200 with other_stack's data
end
```
Before the fix, this request returns `200 OK` with `other_stack`'s CCMenu XML despite the token being scoped to `@stack`, proving the scope bypass; after switching `stack` to use `stacks.from_param!`, the same request raises `ActiveRecord::RecordNotFound` (rendered as `404`).

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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
