### Title
`Api::CCMenuController#stack` bypasses the token's stack scope enforced by `Api::BaseController#stacks` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` defines a `stacks` scope that restricts an `ApiClient` to its own `stack_id` when the token is stack-scoped, and every stack-scoped controller (e.g. `Api::StacksController#stack`) resolves the target stack through that scope via `stacks.from_param!`. `Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, so a `read:stack` token that is scoped to stack A can successfully fetch CCMenu XML (deploy status) for any other stack B.

### Finding Description
The binding that should hold for every `BaseController` subclass is:

`stack accessible under token T == (T.stack_id.present? ? T.stack_id == requested_stack.id : true)`

`Api::BaseController#stacks` implements exactly this: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `#stack` resolves through it: `stacks.from_param!(params[:id])`. [1](#0-0) 

`Api::StacksController` inherits this correctly - its own `#stack` override still calls `stacks.from_param!(params[:id])`, so the scope is preserved. [2](#0-1) 

`Api::CCMenuController`, however, redefines `#stack` to bypass `stacks` entirely and query the bare `Stack` model:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`require_permission :read, :stack` only checks that the permission string `"read:stack"` is present in `ApiClient#permissions`; it never checks `stack_id` against the requested resource. [4](#0-3) 

Root cause: the stack-scoping logic (`current_api_client.stack_id?` guard) lives only in the `stacks` helper on `BaseController`, and `CCMenuController` re-implements resource lookup without reusing that helper, silently dropping the scope check.

Attack: an operator issues an `ApiClient` token restricted to `stack A` (`ApiClient#stack_id = A.id`, `permissions: ['read:stack']`) intended to let a CI/CD dashboard for stack A poll CCMenu status. The holder of that token can call `GET /stacks/:whatever/ccmenu.xml?token=<A's token>&stack_id=<B_param>` (or the equivalent CCMenu route resolving to `Api::CCMenuController#show`) with stack B's `to_param`. `authenticate_api_client` on this controller authenticates via the token param directly (`ApiClient.authenticate(params[:token])`), then `#show` calls `stack` → `Stack.from_param!(params[:stack_id])`, which finds stack B unconditionally and renders its latest deploy/rollback info in the response. [5](#0-4) 

Existing guards don't catch this: `authenticate_api_client` only verifies the token signature and existence, `require_permission!` only checks the permission string, and `stacks.from_param!` (the actual scope enforcement) is simply never invoked by this controller.

### Impact Explanation
A caller holding a `read:stack` token scoped to one stack can read deploy/rollback status (deploy id, `ended_at`, running state, stack name, branch, repository) for any other stack in the installation by guessing/enumerating its `to_param` (owner/repo/environment), which are not secret. This is a cross-tenant read of stack state that the token was never granted, matching the "High - unauthenticated/unauthorized read of stack state or deploy output" impact category. It is fully repeatable against any stack in the instance and requires no interaction beyond issuing one HTTP GET per target stack.

### Likelihood Explanation
Preconditions: the attacker must already hold *some* valid `ApiClient` token with `read:stack` permission (even one deliberately scoped to a single stack by an operator who assumed that scoping was uniformly enforced). Given that, exploitation is a single unauthenticated-relative-to-other-stacks HTTP GET with no other secret required - low attacker cost, fully feasible, and repeatable for every stack in the deployment.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the shared `stacks` scope instead of the bare `Stack` model, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This reuses `Api::BaseController#stacks`, restoring the `current_api_client.stack_id?` scoping check for this controller and eliminating the divergence.

### Proof of Concept
Add to `test/controllers/api/ccmenu_controller_test.rb`:
```ruby
test "#show is scoped to the api client's stack_id and cannot read another stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:shipit_undeployed) # a different stack

  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped-client',
    stack_id: stack_a.id,
    permissions: ['read:stack']
  )

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: token scoped to stack_a must not resolve stack_b.
  assert_response :not_found # currently fails: returns 200 with stack_b's CCMenu XML
end
```
Compare against `Api::StacksController#update`/`#show` with the same scoped client and `stack_b`, which already correctly raises `ActiveRecord::RecordNotFound` (404) because it resolves through `stacks.from_param!`, proving the two controllers diverge on the same credential/resource pair.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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
