### Title
Api::CCMenuController#stack bypasses ApiClient stack_id scoping, allowing cross-stack read - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stack` scopes stack resolution through `stacks`, which filters by `current_api_client.stack_id` when set [1](#0-0) . `Api::CCMenuController` overrides `#stack` to call `Stack.from_param!` directly on the model class, bypassing that scoping entirely [2](#0-1) . This lets a token whose `ApiClient` is scoped to `stack_a` read CCMenu XML status for any other stack `stack_b` by simply changing the `stack_id` param.

### Finding Description
The binding that should hold is: `stack == current_api_client.stacks.find(params[:stack_id])`, i.e. the resolved stack must be an element of `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` as implemented in `Api::BaseController#stacks`/`#stack` [1](#0-0) . Every other API controller inherits this via `stack` or explicitly calls `stacks.from_param!`, e.g. `Api::StacksController#stack` [3](#0-2) .

`Api::CCMenuController` redefines `stack` as:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 
This resolves against `Stack.all` unconditionally, never intersecting with `current_api_client.stack_id`. The permission check only verifies `read:stack` capability in the abstract via `require_permission :read, :stack` → `check_permissions!` [4](#0-3) [5](#0-4) , which does not know or care which stack is being accessed — it never inspects `stack_id`. Nothing else in the request path re-applies the scoping: `authenticate_api_client` only resolves `@current_api_client` from the token [6](#0-5) , and `show` simply calls `stack.deploys_and_rollbacks.last` and renders it [7](#0-6) .

Exploit: attacker holds (or is handed) an `ApiClient` token created with `stack_id = stack_a.id` (e.g., created by an operator scoping the token to their own stack) and permission `read:stack`. Attacker sends `GET /api/1/cc/:stack_id_b.xml?token=...` (or with a query `stack_id` param) for `stack_b`, a stack that token was never meant to access. `Stack.from_param!` resolves `stack_b` successfully because it queries `Stack.all`, and the controller renders `stack_b`'s CCMenu status (name, last build status, last build label, web URL, lock status) — data explicitly meant to be gated by the `stack_id`-scoped token.

### Impact Explanation
This is an unauthenticated-for-that-resource read of another stack's build/deploy status (name, last build status/label/time, lock status, web URL) via a token that was deliberately restricted to a different stack. It matches "High - unauthenticated read of stack state" since the token bypasses its own scoping restriction to read state for a stack it has no authorization over. It is repeatable against arbitrary stacks by varying `stack_id`/`:id` in the URL and requires no elevation of privilege beyond possessing any stack-scoped, `read:stack`-permitted token. Blast radius spans all stacks in the installation, since any scoped token can enumerate any other stack.

### Likelihood Explanation
Preconditions: an `ApiClient` must exist with `stack_id` set to a specific stack (a common configuration pattern for restricting integrations, e.g. CI tooling limited to one project) and permission `read:stack`. The holder of that token need only change the `stack_id` route/query parameter — no additional secrets, signatures, or privileged roles required. This is low-cost and fully repeatable; the only limiting factor is that the attacker must already possess a legitimately-issued, stack-scoped token (not attacker-forged), which is the realistic use case operators rely on for restricting third-party integrations.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the inherited scoping instead of the bare model class:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This reuses `Api::BaseController#stacks`, which already intersects with `current_api_client.stack_id` when present, and removes the need for a controller-specific override entirely (the base implementation could simply be inherited unless CCMenu needs a different param name).

### Proof of Concept
Minitest plan (in `test/controllers/api/ccmenu_controller_test.rb`, mirroring `test/controllers/api/stacks_controller_test.rb`):
1. Create `stack_a = shipit_stacks(:shipit)` and `stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar2"), branch: "main")`.
2. Create/update the test `ApiClient` (`@client`) with `stack_id: stack_a.id` and `permissions: ['read:stack']`.
3. `Api::StacksController` control case: `get :show, params: { id: stack_b.to_param }` scoped by `@client` bound to `stack_a` → assert `assert_response :not_found` (proves `stacks.from_param!` correctly rejects out-of-scope stacks).
4. `Api::CCMenuController` case: `get :show, params: { stack_id: stack_b.to_param }` using the same `@client` bound to `stack_a` → currently asserts `assert_response :ok` and payload `name == stack_b.to_param`, demonstrating the divergence; after the fix this should assert `assert_response :not_found`, matching the `StacksController` behavior in step 3.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
