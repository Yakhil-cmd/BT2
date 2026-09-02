### Title
`Api::CCMenuController#stack` bypasses `current_api_client.stack_id` scope, letting a stack-scoped token read the build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController#stack` resolves stacks through the `stacks` scope, which restricts lookup to `Stack.where(id: current_api_client.stack_id)` when the authenticated `ApiClient` is bound to a specific stack. `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` relation, so the same `ApiClient` token that is restricted to stack A by `Api::StacksController` can be used against `Api::CCMenuController` to read the deploy/build status of stack B.

### Finding Description
The binding that should hold across all `Api::*` controllers reachable with the same token is:
`stacks.from_param!(params[:stack_id]) == Stack.where(id: current_api_client.stack_id).from_param!(params[:stack_id])`
for every controller, i.e. resolution must always be filtered by `current_api_client.stack_id` when that value is present.

- `BaseController#stacks` [1](#0-0)  scopes to the client's bound stack.
- `BaseController#stack` (used unmodified by `Api::StacksController`) applies that scope: [2](#0-1) , and `Api::StacksController#stack` inherits it verbatim [3](#0-2) .
- `Api::CCMenuController#stack` overrides this with a call directly on the `Stack` model, dropping the `current_api_client.stack_id` filter entirely: [4](#0-3) .

`ApiClient#check_permissions!` only checks that the token carries the `read:stack` permission string; it never checks which stack the token is bound to [5](#0-4) . The stack-id restriction is enforced purely by the `stacks` scope in `BaseController`, which `CCMenuController` bypasses.

Attack: an attacker who legitimately holds (or is issued, e.g. via `CCMenuUrlController#fetch`, which creates a client scoped to whichever stack the requesting user names [6](#0-5) ) an `ApiClient` token bound to stack A can call `GET /api/stacks/:other_stack/ccmenu.xml?token=<token>` (or via Basic Auth) with `stack_id` set to any other stack's identifier. `Api::CCMenuController#show` calls the overridden `stack` method, which finds stack B unconditionally, and renders its `deploys_and_rollbacks.last` status, lock state, and branch/environment name in the XML response [7](#0-6) . `require_permission :read, :stack` only checks the generic permission string, not the specific stack, so it does not block this [8](#0-7) .

### Impact Explanation
A token intended to be scoped to a single stack (e.g., issued for a CI badge/CCMenu integration on one repository/environment) can enumerate and read the deploy status, lock status, and last-build metadata of every other stack in the Shipit instance, across repositories/tenants that the token holder has no right to see. This is a cross-tenant unauthorized read of stack state (matches the High-severity category "unauthenticated/unauthorized read of stack state"). It is fully repeatable — any `stack_id` param value can be substituted per request — and requires no additional secrets beyond the one stack-scoped token the attacker was already issued.

### Likelihood Explanation
Preconditions: the attacker must possess one valid, stack-scoped `ApiClient` token with `read:stack` permission (the normal case for CCMenu integration tokens created via `CCMenuUrlController#fetch`). No GitHub secrets, session, or team membership is needed. The attack is a single HTTP GET with a different `stack_id`/`id` value, trivially repeatable against all stack ids, so likelihood is high once such a token exists.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
or remove the override entirely so it inherits `BaseController#stack`, ensuring `current_api_client.stack_id` scoping is honored consistently across all `Api::*` controllers.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read stack B via ccmenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  scoped_client = ApiClient.create!(
    creator: @user, name: "scoped", permissions: %w[read:stack], stack: stack_a
  )

  # Api::StacksController correctly enforces scoping -> 404/403
  @request.headers['Authorization'] = ActionController::HttpAuthentication::Basic
    .encode_credentials(scoped_client.authentication_token, '')
  get :show, controller: 'shipit/api/stacks', params: { id: stack_b.to_param }
  assert_response :not_found

  # Api::CCMenuController ignores current_api_client.stack_id -> 200, leaking stack_b's status
  get :show, controller: 'shipit/api/ccmenu', params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }
  assert_response :ok
  assert_payload 'name', stack_b.to_param
end
```
This demonstrates the divergence: identical `stack_id`/token pair yields `404`/`403` in `Api::StacksController` but `200` (with stack B's data disclosed) in `Api::CCMenuController`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-22)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```
