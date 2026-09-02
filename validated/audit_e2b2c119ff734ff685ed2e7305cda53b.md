### Title
`Api::CCMenuController` bypasses per-client stack scoping, allowing a scoped `ApiClient` to read another stack's status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController` overrides the `stack` helper method to call `Stack.from_param!(params[:stack_id])` directly instead of using the scoped `stacks.from_param!(params[:stack_id])` helper defined in `Api::BaseController`. This means the `current_api_client.stack_id` restriction is never applied for this endpoint, so any valid API token can fetch CCMenu status XML for any stack in the system, not just the one it was issued for.

### Finding Description
The binding claimed broken: `stack.id ∈ {current_api_client.stack_id}` when `current_api_client.stack_id?` is true.

In `Api::BaseController`, the generic scoping is: [1](#0-0) 
`stacks` restricts to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` calls `stacks.from_param!(...)`, enforcing the binding.

`Api::CCMenuController` however redefines `stack` to bypass this scope entirely: [2](#0-1) 
`stack` calls `Stack.from_param!(params[:stack_id])` on the unscoped `Stack` relation. `show` then renders `stack.deploys_and_rollbacks.last` using this unscoped stack.

The only authorization check applied is `require_permission :read, :stack`, which only calls `current_api_client.check_permissions!('read', 'stack')` — a check against the client's permission list, unrelated to `stack_id`: [3](#0-2) 
This check passes for any client with `read:stack` in its permissions regardless of which `stack_id` it is scoped to, or even for unscoped clients (`stack_id?` false).

Attacker flow: attacker has (or previously obtained, e.g. from a CCMenu badge URL) a valid `token` for an `ApiClient` scoped to stack A with `read:stack` permission. They issue `GET /api/stacks/:owner/:repo/:branch/ccmenu.xml?token=...` (or via Basic Auth) with `stack_id` corresponding to stack B instead of A. `authenticate_api_client` in `CCMenuController` only verifies the token is valid via `ApiClient.authenticate(params[:token])`, never checking `stack_id`: [4](#0-3) 
`require_permission!` passes because the permission check is scope-name based, not stack-instance based. `stack` resolves stack B unscoped. `show` renders stack B's latest deploy/rollback status.

### Impact Explanation
An attacker holding a token for one stack can read deploy/task status (build success/failure, lock state, last build label/time) of any other stack in the Shipit instance by simply changing the `stack_id` in the request path/params. This is an authorization-scope violation: unauthenticated-for-that-resource read of stack state, matching the High severity category ("escalation... unauthenticated read of stack state, task streams or deploy output"). It is fully repeatable against arbitrary stacks and requires only one valid, even narrowly-scoped, `ApiClient` token.

### Likelihood Explanation
Preconditions are modest and realistic: at least one stack-scoped `ApiClient` must exist (a common configuration for CI-badge-style CCMenu tokens), and the attacker must possess that client's token (plausible since CCMenu URLs, including the token, are commonly embedded in public build badges/READMEs as the question notes). No GitHub secrets, session, or elevated role are required — only the leaked/legitimate CCMenu token. Given the endpoint is specifically designed for this token-based, no-session use case, likelihood of misuse if a token is exposed is high.

### Recommendation
In `Api::CCMenuController`, remove the local `stack` override and rely on the inherited scoped `stack` method from `Api::BaseController` (i.e., use `stacks.from_param!(params[:stack_id])`) so `current_api_client.stack_id` scoping is enforced, matching the behavior of other API controllers (e.g., `Api::StacksController`, `Api::DeploysController`).

### Proof of Concept
Minitest plan (in `test/controllers/api/ccmenu_controller_test.rb` style, using existing `ApiControllerTestCase` helpers):
1. Create two stacks, `stack_a` and `stack_b` (e.g. via fixtures `shipit_stacks(:shipit)` and a newly created `Stack`).
2. Create an `ApiClient` scoped to `stack_a` (`stack: stack_a`) with `permissions: ['read:stack']`, and authenticate as that client (set `token`/Basic Auth as in `authenticate!`).
3. `get :show, params: { stack_id: stack_b.to_param }`.
4. Assert `response.status == 200` (not 403/404).
5. Assert the binding divergence explicitly: `assert_not_equal current_api_client.stack_id, stack_b.id` and that the rendered XML/`assigns(:stack)&.id` (or parsed CCMenu `name` attribute) corresponds to `stack_b`, proving cross-stack disclosure despite the client being scoped to `stack_a`.

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
