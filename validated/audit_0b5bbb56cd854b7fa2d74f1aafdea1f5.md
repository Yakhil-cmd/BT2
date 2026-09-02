### Title
`CCMenuController#stack` bypasses `current_api_client.stack_id` scoping, allowing cross-stack read via `read:stack` permission - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the base controller's `stack` accessor with a private method that resolves the target stack directly via `Stack.from_param!(params[:stack_id])`, instead of using the base class's scoped `stacks.from_param!(params[:stack_id])`. As a result, `check_permissions!` only ever validates that the string `read:stack` is present in `current_api_client.permissions`; it never verifies that `current_api_client.stack_id` equals the id of the stack the request is actually targeting.

### Finding Description
The binding that should hold for this endpoint to be tenant-safe is:
`current_api_client.stack_id == stack.id` (the id of the stack whose CCMenu data is rendered), whenever `current_api_client.stack_id?` is true.

Trace:
- `BaseController#stacks` correctly encodes this binding: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) , and `BaseController#stack` resolves through that scope: `@stack ||= stacks.from_param!(params[:stack_id])` [2](#0-1) . `StacksController` relies on this scoped accessor as well (`stacks.from_param!(params[:id])`) [3](#0-2) .
- `CCMenuController`, however, defines its own private `stack` method that ignores the scope entirely: `@stack ||= Stack.from_param!(params[:stack_id])` [4](#0-3) . This method is used by `show` to render the CCMenu XML for whatever stack the id/slug resolves to across the entire `Stack` table [5](#0-4) .
- The permission check itself, `require_permission :read, :stack` → `require_permission!` → `current_api_client.check_permissions!(operation, scope)`, only checks the permission string, never the stack identity: `unless permissions.include?(required_permission) ... raise InsufficientPermission` [6](#0-5) .

Because `CCMenuController#stack` never consults `current_api_client.stack_id`, the equality is not merely broken under the id-reuse edge case the question hypothesizes — it is never checked at all in this controller, even without any deletion/reuse of stack ids. Any `ApiClient` token holding the `read:stack` permission (issued/scoped to stack A) can be replayed as `GET /stacks/<any-other-stack-id-or-slug>/ccmenu?token=<token>` to read the CCMenu status (latest deploy/rollback state) of an arbitrary, unrelated stack B, simply by changing `params[:stack_id]` in the URL. The stale-token/id-reuse scenario described in the question is a strict subset of this broader, always-reachable bypass.

None of the existing guards prevent this: `authenticate_api_client` in `CCMenuController` only verifies the token signature (`ApiClient.authenticate(params[:token])`) [7](#0-6) ; `require_permission!`/`check_permissions!` checks only the permission name, not stack identity [6](#0-5) ; and `stack` (as overridden in this controller) performs no scoping by `current_api_client.stack_id`.

### Impact Explanation
An attacker who holds any valid `ApiClient` token granting `read:stack` (even one legitimately scoped to a single stack they own) can read the CI/deploy status (latest deploy id, timestamp, running state) of any other stack in the installation by iterating `stack_id`/slug values in the CCMenu URL. This is repeatable against arbitrary stacks/tenants with no rate limiting relevant to scope, and matches "unauthenticated/unauthorized read of stack state" — High severity per the given categories. It does not grant write/deploy/command execution capability, only read of stack deploy status via this specific endpoint.

### Likelihood Explanation
Preconditions: attacker must possess some valid `ApiClient` token with the `read:stack` permission (e.g., a legitimately issued CCMenu token for their own stack, which Shipit operators commonly hand out for CI dashboard integration). No secrets, GitHub credentials, or elevated roles are required beyond having once been issued such a token. The attack is a single unauthenticated GET request with a substituted `stack_id`, trivially repeatable and scriptable.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped lookup consistent with the rest of the API, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, reusing `BaseController#stacks`, so that `current_api_client.stack_id` (when present) is enforced against the requested stack, matching the pattern already used in `StacksController`.

### Proof of Concept
Minitest plan (`test/controllers/shipit/api/ccmenu_controller_test.rb`):
1. Create `stack_a = shipit_stacks(:shipit)` (or a new stack) and `stack_b`, a distinct stack.
2. Create an `ApiClient` with `permissions: ['read:stack']` and `stack_id: stack_a.id`; get `token = api_client.authentication_token`.
3. `get :show, params: { stack_id: stack_b.to_param, token: token }`.
4. Assert both sides of the binding: expected `current_api_client.stack_id (stack_a.id) == stack.id` should hold for authorized access; actual: `response.status` is `200` and the rendered XML corresponds to `stack_b` (e.g., contains `stack_b`'s latest deploy data), proving `stack.id == stack_b.id != stack_a.id == current_api_client.stack_id`, i.e., the binding is violated and access is granted anyway.
5. Contrast with `StacksController#show` using the same token/stack_b combination, which correctly raises `ActiveRecord::RecordNotFound` (via `stacks.from_param!`) because `stacks` is scoped to `stack_a` only — demonstrating the CCMenu controller's divergence from the rest of the API.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L78-80)
```ruby
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
