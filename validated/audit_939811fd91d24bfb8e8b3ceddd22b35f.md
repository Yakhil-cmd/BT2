### Title
CCMenuController#stack bypasses `current_api_client.stack_id` scoping, exposing arbitrary stacks' deploy status to a token limited to a different stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides `BaseController#stack` with `Stack.from_param!(params[:stack_id])`, ignoring the `stacks` helper (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) that other controllers such as `StacksController` use to enforce stack scoping. Combined with `require_permission :read, :stack`, which only checks the `read:stack` permission string via `ApiClient#check_permissions!` and never inspects `current_api_client.stack_id`, an `ApiClient` token scoped to stack A can fetch CCMenu XML (build status, activity, last build label/time, webUrl) for any other stack B.

### Finding Description
The binding that should hold is: `stack.id == current_api_client.stack_id` (when `current_api_client.stack_id?` is true) for any stack object returned to a scoped token. This binding is enforced in `app/controllers/shipit/api/base_controller.rb`: [1](#0-0) 
via `stacks.from_param!`, and it is correctly used by `StacksController#stack`: [2](#0-1) 

However, `CCMenuController` defines its own `#stack` that calls `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `stacks` scope: [3](#0-2) 

The `require_permission :read, :stack` before_action only calls `require_permission!(:read, :stack)`, which delegates to `current_api_client.check_permissions!(:read, :stack)`: [4](#0-3) [5](#0-4) 
This method checks only the `permissions` array (e.g. `["read:stack"]`) against the operation/scope string; it has no reference to `params[:stack_id]` or any stack instance, so it cannot and does not enforce which stack is being read. The scoping is supposed to happen later, when the stack is resolved, via the `stacks` helper — but `CCMenuController` never calls `stacks`, so the scoping never happens for this controller.

Attacker flow: attacker holds (or is issued) a valid `ApiClient` token whose `stack_id` is set to stack A and whose `permissions` include `read:stack` (a legitimate, narrowly-scoped credential an operator might issue for CI status badges). The attacker requests `GET /api/stacks/:stack_id/cc.xml` (CCMenuController#show route) with `stack_id` set to stack B's id/param, using the token for stack A. `authenticate_api_client` succeeds (valid token), `require_permission!(:read, :stack)` succeeds (permission present), and `stack` resolves unscoped to stack B, disclosing stack B's build status/activity/lastBuildLabel/lastBuildTime/webUrl.

Existing guards do not prevent this: `verify_signature`/webhook validation is irrelevant (this is an authenticated API GET, not a webhook); `EnvironmentVariables#permit` is irrelevant; model validators are irrelevant; `require_permission!` is, by design/implementation, incapable of scope-instance checks; and the `stacks` helper that would fix this is simply not used by this controller.

### Impact Explanation
A holder of a stack-A-scoped, `read:stack`-only API token can read stack B's (or any stack's) CI/deploy status — name, activity, last build status/label/time, web URL — for stacks they were never granted access to. This is a cross-tenant unauthorized read of stack state via a legitimately-scoped credential escaping its intended scope, repeatable for every stack id in the system with a single request per stack. This matches the "High - unauthenticated/[here: out-of-scope-authenticated] read of stack state" impact category listed in the rules.

### Likelihood Explanation
Preconditions: attacker must already possess *some* valid `ApiClient` token (any token, even one intentionally scoped to a single, low-privilege stack, e.g. issued for a public CI-status badge integration). No GitHub secrets, session, or maintainer role needed. Given such a token — which is exactly the kind of narrowly-scoped credential Shipit operators are led to believe is "stack B; permissions=read:stack" implicitly means "only stack A" — the attack is a single unauthenticated-cost HTTP GET with a different `stack_id` param. Feasibility is high and fully repeatable across all stacks.

### Recommendation
Change `CCMenuController#stack` to use the scoped helper, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private override entirely so it inherits `BaseController#stack`/`#stacks`, restoring the `current_api_client.stack_id` scoping that `StacksController` and others rely on.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to one stack cannot read another stack's CCMenu status" do
  scoped_stack = shipit_stacks(:shipit)
  other_stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar2"), branch: 'main')

  @client.update!(stack_id: scoped_stack.id, permissions: ['read:stack'])

  get :show, params: { stack_id: other_stack.to_param }

  # Binding under test: stack.id == current_api_client.stack_id
  # Expected (secure): request rejected because other_stack.id != scoped_stack.id
  assert_response :not_found # or :forbidden, NOT :ok
end
```
Running this against current code shows `assert_response :ok` with `other_stack`'s data returned, proving the scoping bypass; after applying the recommended fix (`stacks.from_param!`), the request raises `RecordNotFound`/404 because `other_stack.id` is not in `Stack.where(id: scoped_stack.id)`.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
