### Title
CCMenu controller bypasses `ApiClient#stack_id` scoping, allowing stack-scoped tokens to read any stack's status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, instead of using the inherited `stacks` method that restricts lookups to `current_api_client.stack_id` when the token is bound to a single stack. Combined with `check_permissions!`, which only checks the string `"read:stack"` against the client's `permissions` array without any awareness of which stack the client is scoped to, a token minted for stack A with `read:stack` permission can be replayed to read the CCMenu XML of an unrelated stack B.

### Finding Description
The intended binding, enforced in `BaseController`, is:
`current_api_client.stack_id? ? (stack.id == current_api_client.stack_id) : true`
implemented via [1](#0-0) 
`stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client has a bound `stack_id`, and `stack` (used by every other controller such as `StacksController`) resolves `params[:id]`/`params[:stack_id]` through that scoped relation, e.g. `stacks.from_param!(params[:id])`: [2](#0-1) 

`CCMenuController` does not reuse this. It defines its own `#stack`: [3](#0-2) 
which calls `Stack.from_param!(params[:stack_id])` on the entire `Stack` table, completely ignoring `current_api_client.stack_id`. The permission gate, `require_permission :read, :stack` at line 6, only calls `current_api_client.check_permissions!(:read, :stack)`: [4](#0-3) 
which merely checks `permissions.include?("read:stack")` — it never compares `stack.id` to `current_api_client.stack_id`. So for a client whose row has `stack_id = A` and `permissions = ["read:stack"]`, a request `GET /stacks/:owner/:repo/:env/cc_menu.xml?token=<A's token>` (or with basic-auth) for stack B's `stack_id` param passes `check_permissions!` (permission string present) and passes `stack` resolution (unscoped lookup finds B), returning `200 OK` with B's CCMenu status.

Root cause: `CCMenuController#stack` diverges from the codebase-wide convention of routing all stack lookups through the `stacks` scoping method, silently dropping the per-client stack binding that `check_permissions!` was never designed to enforce on its own.

Existing guards do not catch this: `verify_signature`/webhook checks are irrelevant (this is a plain API GET, not a webhook), `ExplicitParameters` doesn't validate cross-object scoping, and `require_permission!`/`check_permissions!` only checks the permission string, by design relying on `stack`/`stacks` for the stack-binding enforcement that `CCMenuController` skips.

### Impact Explanation
Any holder of a valid `ApiClient` token bound to one stack and granted only `read:stack` on that stack can read the build/deploy status (last build status, label, activity, web URL) of any other stack in the Shipit instance, including stacks belonging to unrelated repositories/tenants. This is an authorization bypass matching "unauthorized read of stack state" (High severity per the rubric). It is fully repeatable — one request per target stack, with no rate limiting bypass needed — and the blast radius spans every stack in the installation, not just the one the token was issued for.

Note: per the rules, an attacker must hold a valid `ApiClient` token to exploit this (a scoped client credential, not a Shipit session or GitHub secret). This is a real precondition, but it directly contradicts the intended purpose of `ApiClient#stack_id` scoping (limiting a client's blast radius to its own stack), so a token issued narrowly for one integration ends up leaking cross-tenant data.

### Likelihood Explanation
Preconditions: attacker needs one legitimately-issued `ApiClient` record with `stack_id` set and `permissions` including `read:stack` (a common, low-privilege credential intended for a single stack's CI status badge integration). No GitHub secrets, session, or team membership required. Given such a token, exploitation is a single unauthenticated-relative-to-other-stacks GET request; cost is negligible and it is trivially repeatable against every stack ID in the system.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` method instead of the raw `Stack` relation, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so that a client bound to a specific stack cannot resolve any other stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped client cannot read another stack's CCMenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  @client.update!(stack_id: stack_a.id, permissions: ['read:stack'])

  get :show, params: { stack_id: stack_b.to_param, token: @client.authentication_token }

  # Binding under test: current_api_client.stack_id (stack_a.id) must equal stack.id (stack_b.id)
  # for the request to be authorized. They differ, so this must NOT be 200.
  assert_not_equal @client.stack_id, stack_b.id
  assert_response :not_found # or :forbidden — currently wrongly returns :ok
end
```
This test, run against the current code, will show the request incorrectly returning `200 OK` with stack B's XML payload, proving the cross-stack read.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
