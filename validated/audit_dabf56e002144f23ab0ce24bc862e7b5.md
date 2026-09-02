### Title
`CCMenuController#stack` bypasses `current_api_client.stack_id` scoping via bare `Stack.from_param!` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stacks` restricts the visible stack set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and every other subclass resolves the requested stack via `stacks.from_param!(...)` so that restriction is enforced. `Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the `Stack` class, never touching `stacks`, so a token scoped to one stack can fetch CCMenu XML for any other stack.

### Finding Description
The intended binding is: for any API request, `resolved_stack ∈ current_api_client.stack_id? ? {stack A} : Stack.all`, enforced by `Api::BaseController#stacks` [1](#0-0) . `Api::StacksController#stack` and other subclasses honor this by calling `stacks.from_param!(params[:id])` [2](#0-1) .

`Api::CCMenuController` instead defines its own `#stack` that calls the bare class method `Stack.from_param!(params[:stack_id])`, bypassing the `stacks` scope entirely, and also overrides `authenticate_api_client` to accept `params[:token]` for query-string authentication [3](#0-2) . The only authorization check applied is `require_permission :read, :stack`, which calls `ApiClient#check_permissions!` — this only checks that the string `"read:stack"` is present in `permissions`; it never consults `stack_id` [4](#0-3) . So `resolved_stack` for this controller is unconstrained by `current_api_client.stack_id`, breaking the binding for any client that holds `read:stack` permission, regardless of its `stack_id` scoping.

Exploit: an operator creates an `ApiClient` with `stack_id: A.id` (via `Api::ApiClientsController`) intending to scope it to repository/stack A only, with permission `read:stack`. The attacker holding that token requests `GET /api/stacks/<B_owner>/<B_name>/<B_env>/ccmenu?token=<tokenA>`. `CCMenuController#show` resolves `stack` via the unscoped `Stack.from_param!`, finds stack B (a different repository), and renders `shipit/ccmenu/project` with B's `deploys_and_rollbacks`, build status, label and web URL [5](#0-4) . No existing guard (`require_permission`, `check_permissions!`, `authenticate_api_client`) validates that B matches the client's `stack_id`.

### Impact Explanation
The attacker obtains unauthenticated-for-that-repo, cross-tenant read access to another repository's build/deploy status (last build status, last build label, activity, web URL) using a token that was provisioned to be scoped to a single stack. This is repeatable against arbitrary stacks by simply varying `stack_id` in the URL, since the query parameter is fully attacker-controlled and the route accepts any `stack_id_format` matching `owner/name/environment`. This matches "unauthenticated read of stack state" (High) — the token was authorized only for stack A but reads stack B's state, which is a cross-tenant read that the `stack_id` scoping mechanism explicitly exists to prevent.

### Likelihood Explanation
Preconditions are realistic and low-cost: any legitimate operator who provisions a stack-scoped `ApiClient` (a normal, encouraged least-privilege configuration, e.g., for a build server posting CI status) creates the exact precondition. The attacker only needs possession of that one token (e.g., embedded in CI config, logs, or a third-party integration) and knowledge/enumeration of another stack's `owner/name/environment` triple, which is often guessable or public (GitHub repo names). No GitHub secrets, session, or additional privilege is required — this is directly reachable via a single unauthenticated-except-for-token GET request.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped `stacks.from_param!(params[:stack_id])` (inherited from `BaseController`) instead of the bare `Stack.from_param!(params[:stack_id])`, consistent with `StacksController` and all other subclasses, so that a `stack_id`-scoped `ApiClient` cannot resolve a stack outside its scope.

### Proof of Concept
In `test/controllers/api/ccmenu_controller_test.rb` (minitest, `ApiControllerTestCase`):
1. Create `stack_a = shipit_stacks(:shipit)` and a second stack `stack_b = Stack.create!(repository: Repository.create!(owner: "other", name: "repo"), branch: "main")` with a different `repository_id`.
2. Create an `ApiClient` scoped to A: `client = ApiClient.create!(creator: @user, name: 'scoped', stack_id: stack_a.id, permissions: ['read:stack'])`.
3. `get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }`.
4. Assert the binding: expected (fixed) — `assert_response :not_found` (stack B is outside `stacks` scope for this client, so `from_param!` should raise `RecordNotFound`/404); actual (bug, current code) — `assert_response :ok` and `assert_equal stack_b.to_param, Hash.from_xml(response.body)['Projects']['Project']['name']`, proving cross-stack data leaked to a token scoped only to stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
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
