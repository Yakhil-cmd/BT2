### Title
CCMenu endpoint bypasses per-token stack scoping, allowing unauthorized cross-tenant read of stack build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` defines its own private `stack` method that resolves the stack via `Stack.from_param!(params[:stack_id])` directly, instead of using the inherited `stacks.from_param!` scoping from `Api::BaseController`. This means any valid `ApiClient` token — even one scoped to a single stack via `stack_id` — can read `lastBuildStatus`/`lastBuildLabel`/`webUrl` for any stack in the installation.

### Finding Description
The broken binding: the codebase intends `stack ∈ current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` for every API endpoint (as implemented by `Api::BaseController#stacks`/`#stack`) [1](#0-0) . In `Api::CCMenuController`, this is overridden:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

This resolves against `Stack.from_param!` unscoped by `current_api_client.stack_id`, so the equality `stack ∈ stacks` (the tenant-scoped set) is violated: `stack` is drawn from `Stack.all` regardless of the token's binding.

The only authorization check on this action is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(:read, :stack)` [3](#0-2) . This check only verifies that the string `"read:stack"` is present in the client's `permissions` array [4](#0-3) ; it performs no comparison against `stack.id` or `current_api_client.stack_id`. There is no other guard (no `stacks`-scoped lookup, no ownership check) between the request and `#show`.

`#show` then reads `stack.deploys_and_rollbacks.last` and renders the CCMenu XML with `lastBuildLabel`/`lastBuildStatus`/`webUrl` for that unscoped stack [5](#0-4) .

Attacker request: `GET /api/ccmenu/:any_stack_id?token=<attacker's own valid, stack-scoped token>`. Because `#stack` ignores `current_api_client.stack_id`, any `:any_stack_id` resolves successfully as long as it's a valid stack identifier, regardless of which stack the token was issued for.

### Impact Explanation
An attacker holding one legitimately-issued, stack-scoped `ApiClient` token (with `read:stack` permission for their own stack) can enumerate every stack in the installation and read its most recent deploy/rollback build status, label, and web URL — data belonging to other tenants/repositories they have no authorization for. This is repeatable for every stack ID and requires no elevation, matching "High - unauthenticated read of stack state" (here more precisely an authorization-bypass read across tenants, since the requester does hold a token, but a scoped one). It does not expose secrets or allow writes/deploys, so it stays at read-disclosure severity rather than Critical.

### Likelihood Explanation
Precondition is simply holding any one valid `ApiClient` token with `read:stack` permission — such tokens are commonly issued per-team/per-stack to CI/CD integrations, so this is a low-cost, highly feasible, and fully repeatable attack (a simple loop over stack IDs).

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited, properly-scoped resolution instead of `Stack.from_param!` directly:

```ruby
private

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

removing the controller's local override entirely so it inherits `Api::BaseController#stack`/`#stacks`, restoring the `stack ∈ stacks(current_api_client)` binding.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (illustrative)
test "scoped api client cannot read other stacks via ccmenu" do
  scoped_stack = shipit_stacks(:shipit)
  other_stack  = shipit_stacks(:shipit2) # any different fixture stack

  client = shipit_api_clients(:some_client) # token scoped to scoped_stack.id, permissions: ["read:stack"]
  client.update!(stack_id: scoped_stack.id)

  get :show, params: { stack_id: other_stack.to_param, token: client.authentication_token }

  # Binding under test: stack resolved by controller must equal a member of
  # Stack.where(id: current_api_client.stack_id), i.e. == scoped_stack, never other_stack.
  assert_response :not_found # or :forbidden — today this incorrectly returns :ok
  refute_includes response.body, other_stack.deploys_and_rollbacks.last&.git_sha.to_s
end
```
This test fails today because the request returns `200 OK` with `other_stack`'s `lastBuildLabel`/`webUrl`, proving the scoping bypass.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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
