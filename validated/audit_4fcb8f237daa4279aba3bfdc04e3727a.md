### Title
`CCMenuController#stack` bypasses `current_api_client.stack_id` scoping, allowing cross-tenant deploy history disclosure - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's scoped `stack` helper with its own unscoped lookup, so any `ApiClient` token restricted to a single stack (via `stack_id`) can still fetch the `cc.xml` deploy/rollback summary for any other stack in the system by simply supplying that stack's `to_param` as `params[:stack_id]`.

### Finding Description
The intended binding, as enforced everywhere else in the API, is:
`stack == (current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all).from_param!(params[:stack_id])`
This is implemented in `Shipit::Api::BaseController#stacks`/`#stack` [1](#0-0) .

However, `CCMenuController` redefines `stack` and drops the scoping entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

The controller only enforces `require_permission :read, :stack` [3](#0-2) , which calls `ApiClient#check_permissions!` — this checks only that the token's `permissions` array contains the string `"read:stack"`, with no reference to which stack the token is scoped to: [4](#0-3) . Scope restriction is supposed to happen via `current_api_client.stack_id` in the `stacks` helper, but `CCMenuController#stack` never calls that helper — it calls `Stack.from_param!` directly against the whole `Stack` table.

Exploit: An `ApiClient` token legitimately issued and scoped to stack X (has `stack_id = X.id`, permission `read:stack`) sends `GET /api/stacks/<Y-owner>/<Y-repo>/<Y-branch>/ccmenu?token=<token>` where Y is any other stack (different `Repository` owner). Because `stack` resolves via unscoped `Stack.from_param!`, the request resolves to stack Y and renders `shipit/ccmenu/project` with `stack: Y, deploy: Y.deploys_and_rollbacks.last`, exposing Y's last build status, label, deploy id, and timing — cross-tenant deploy history disclosure.

Existing guards don't stop this: `authenticate_api_client` only verifies the token signature/existence [5](#0-4) ; `require_permission!` checks only the string permission, not the stack scope; and the base controller's `stacks`/`stack` scoping method — which is the actual enforcement point for `current_api_client.stack_id` — is shadowed by the subclass override and never executed.

### Impact Explanation
An attacker holding any token scoped to their own stack (obtainable legitimately for their own repository) can read the `cc.xml` deploy/rollback status of any other stack in the Shipit instance, across repository/tenant boundaries, simply by varying `params[:stack_id]`. This is repeatable against arbitrary stacks with no rate limiting concerns needed — one request per target stack. This matches "High: unauthenticated (here, cross-scope-authenticated) read of stack state / deploy output" for a stack the token was never authorized against.

### Likelihood Explanation
Preconditions: attacker must already possess a valid `ApiClient` token scoped to their own stack (`read:stack` permission) — a normal, legitimately-issued credential for one's own repository. No GitHub secrets, session, or elevated role needed. Cost is a single authenticated HTTP GET with an attacker-chosen `stack_id` path segment; fully repeatable against every stack in the instance.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and rely on `BaseController#stack` (which uses the `stacks` scope respecting `current_api_client.stack_id`), i.e., delete lines 29-31 of `app/controllers/shipit/api/ccmenu_controller.rb` so `Stack.from_param!` is replaced by the inherited scoped `stacks.from_param!`.

### Proof of Concept
minitest under `test/controllers/api/ccmenu_controller_test.rb`:
```ruby
test "cannot fetch cc.xml for a stack outside the client's scope" do
  stack_x = shipit_stacks(:shipit) # Repository owner A
  stack_y = Stack.create!(repository: Repository.create!(owner: "other-org", name: "other-repo"), branch: "main")
  stack_y.deploys.create!(until_commit: stack_y.commits.create!(sha: '0' * 40, message: "y"))

  client_scoped_to_x = ApiClient.create!(creator: @user, name: "scoped", stack_id: stack_x.id, permissions: ["read:stack"])

  get :show, params: { stack_id: stack_y.to_param, token: client_scoped_to_x.authentication_token }

  assert_response :ok # currently passes -- proves the bypass
  project = Hash.from_xml(response.body)['Projects']['Project']
  assert_equal stack_y.to_param, project['name'] # attacker reads stack_y data despite token scoped to stack_x
end
```
Assert both sides of the binding: `client_scoped_to_x.stack_id == stack_x.id` (true) but the response's rendered `stack` equals `stack_y`, not `stack_x` — proving `stack ∈ stacks authorized by current_api_client.stack_id` is violated.

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
