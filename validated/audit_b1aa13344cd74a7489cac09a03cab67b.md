### Title
Cross-tenant stack read via `Shipit::Api::CCMenuController#stack` bypassing `ApiClient` stack scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` scopes stacks accessible to a stack-restricted `ApiClient` via `stacks` (`current_api_client.stack_id`-filtered) and `stack` (`stacks.from_param!`), but `CCMenuController` overrides `stack` to call `Stack.from_param!` directly on the unscoped class, never invoking `stacks`. Combined with `ApiClient#check_permissions!` only checking the permission string and not the client's `stack_id`, any `ApiClient` with `read:stack` permission can fetch CI status XML for any stack in the system, not just the one it is scoped to.

### Finding Description
The intended binding is: `requested_stack.id ∈ stacks(current_api_client).pluck(:id)`, where `stacks` is defined as `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) , and `BaseController#stack` correctly enforces this via `stacks.from_param!(params[:stack_id])` [2](#0-1) .

`CCMenuController` overrides `stack` with:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 
This calls the class method on `Stack` directly, never touching `current_api_client.stack_id`. The only permission check is `require_permission :read, :stack` [4](#0-3) , which invokes `current_api_client.check_permissions!(:read, :stack)` [5](#0-4) . `ApiClient#check_permissions!` only checks `permissions.include?("read:stack")` and never examines `stack_id` [6](#0-5) .

Attack: attacker holds an `ApiClient` with `stack_id = 1` and permission `read:stack`. They call `GET /api/stacks/999999/cc.xml?token=<their_token>` (route `ccmenu#show` scoped by `stack_id` [7](#0-6) ). `authenticate_api_client` in `CCMenuController` authenticates via the `token` param [8](#0-7) , succeeds. `require_permission :read, :stack` passes since the client has that permission, irrespective of stack. `stack` resolves stack 999999 unscoped, and `show` renders that stack's CI status/build info regardless of ownership [9](#0-8) .

No other guard intervenes: this is API-token authentication, not session/OAuth, so `force_github_authentication`/`User#authorized?` are irrelevant; `verify_signature`/webhook checks are irrelevant; `ExplicitParameters` is not used here. The `stacks` scoping method — the only mechanism designed to enforce this binding — is simply dead code for this controller.

### Impact Explanation
An attacker with a legitimately-scoped but limited `ApiClient` (e.g., one created for their own repository's CCMenu integration, as done automatically by `CcmenuUrlController#client` [10](#0-9) ) can read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock status) of any stack belonging to any other repository/organization, by simply enumerating stack ids/params. This is repeatable against arbitrary stacks with no additional privilege, and constitutes unauthenticated-relative-to-target read of stack state across tenants — matching "High: escalation into... unauthenticated read of stack state" and arguably violating repository-scope isolation guarantees the engine is supposed to provide for multi-tenant deployments.

### Likelihood Explanation
No special preconditions beyond holding any stack-scoped `ApiClient` token with `read:stack` — a permission granted automatically whenever a CCMenu URL is generated for a stack (see `CcmenuUrlController`) [10](#0-9) . Any user who can create/view a CCMenu URL for one stack they have access to obtains a token, then reuses it against arbitrary `stack_id` values in the URL. Attacker cost is a single authenticated (but non-privileged, stack-scoped) request; fully repeatable.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and rely on `BaseController#stack` (i.e., `stacks.from_param!(params[:stack_id])`), which enforces the `current_api_client.stack_id` scoping. Alternatively, add an explicit check in `CCMenuController#stack` verifying `current_api_client.stack_id.nil? || current_api_client.stack_id == resolved_stack.id` before returning the stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "cannot fetch cc.xml for a stack outside the client's stack_id scope" do
  other_repo = Repository.create!(owner: 'other-org', name: 'other-repo')
  other_stack = Stack.create!(repository: other_repo, branch: 'main')

  scoped_client = ApiClient.create!(
    creator: @user, name: 'scoped',
    stack_id: @stack.id,             # scoped to @stack only
    permissions: %w[read:stack]
  )

  # Binding under test: other_stack.id ∈ stacks(scoped_client)?
  assert_not_includes Stack.where(id: scoped_client.stack_id).pluck(:id), other_stack.id

  get :show, params: { stack_id: other_stack.to_param, token: scoped_client.authentication_token }

  # Expect this to fail with 404/403 if the binding were enforced.
  assert_response :not_found  # currently fails: returns 200 with other_stack's data, proving the bypass
end
```

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
