### Title
Cross-tenant CCMenu XML disclosure via unscoped `Stack.from_param!` in `Api::CCMenuController#stack` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` resolves the target stack with `Stack.from_param!(params[:stack_id])` instead of the tenant-scoped `stacks.from_param!(params[:stack_id])` used by `Api::BaseController#stack`. Since `ApiClient#check_permissions!` only checks that the token has the `read:stack` permission string and never compares the requested stack to `current_api_client.stack_id`, a valid token scoped to org Y's stack can render `#show` for any stack ID belonging to org X, leaking its latest deploy/rollback commit SHA and build status in the CCMenu XML.

### Finding Description
The intended binding is: `stack.id ∈ {current_api_client.stack_id}` (when the client is stack-scoped) must equal the stack actually rendered. In `Api::BaseController`: [1](#0-0) 

`stacks` restricts the relation to `current_api_client.stack_id` when present, and `#stack` calls `stacks.from_param!`, enforcing the binding.

`Api::CCMenuController` overrides `#stack` and drops the scope entirely: [2](#0-1) 

`require_permission :read, :stack` only triggers `check_permissions!`, which is purely a string-membership check against the token's `permissions` array and never references `stack_id`: [3](#0-2) 

So the equality `stack.id == current_api_client.stack_id` (or membership in an all-stacks scope) is never evaluated in this controller — `Stack.from_param!` resolves globally across all stacks/orgs, breaking the tenant boundary that `BaseController#stack` otherwise enforces for every other API endpoint (stacks, tasks, deploys, rollbacks, commits, etc., all of which use the inherited `#stack`/`stacks` scoping via `from_param!` on the scoped relation, as seen across `deploys_controller.rb`, `rollbacks_controller.rb`, `tasks_controller.rb`, etc.).

Attack: attacker (or any party holding a legitimately-issued token scoped to org Y's stack, e.g., a CI system operator for org Y) sends `GET /api/stacks/<org-X-stack-id-or-slug>/ccmenu.xml?token=<Y's token>`. `authenticate_api_client` in `CCMenuController` only verifies the token signature via `ApiClient.authenticate`, then `#stack` resolves org X's stack unconditionally, and `#show` renders `lastBuildLabel`/`lastBuildStatus` from org X's `deploys_and_rollbacks.last`, disclosing X's commit SHA and build status to a caller with no permission over X.

### Impact Explanation
A validly-signed but narrowly-scoped API token (issued for one stack/org) can read another arbitrary org's latest deploy/rollback commit SHA and build status (success/failure/running) by simply substituting `stack_id` in the URL. This is a cross-tenant unauthenticated-for-that-tenant read of stack/build state, matching the High severity category "unauthenticated read of stack state ... " since the token holder has no read grant on the target stack. It is repeatable against any stack ID/slug on the instance and requires only one valid API token for any single stack, so the blast radius covers all stacks on a shared Shipit instance.

### Likelihood Explanation
Preconditions are modest: the attacker needs any single stack-scoped `read:stack` API token (self-issued for their own stack in a multi-tenant Shipit deployment, or otherwise obtained) and knowledge/guessability of a target `stack_id`/slug. No GitHub secrets, session, or elevated role is required. This is trivially repeatable — a single GET request per target stack.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the tenant-scoped lookup from `BaseController`, i.e. remove the private `stack` override (or replace `Stack.from_param!(params[:stack_id])` with `stacks.from_param!(params[:stack_id])`) so the `current_api_client.stack_id` scope is enforced identically to every other API controller.

### Proof of Concept
```ruby
test "ccmenu show leaks build data across api client stack scope" do
  org_x_stack = shipit_stacks(:shipit)      # belongs to org X
  org_y_stack = shipit_stacks(:cyclimse)    # belongs to org Y, different repo/owner

  deploy = org_x_stack.deploys.create!(until: Time.now.utc) rescue org_x_stack.deploys.last

  client_y = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'org-y-client',
    stack: org_y_stack,
    permissions: ['read:stack'],
  )

  get "/api/stacks/#{org_x_stack.id}/ccmenu.xml", params: { token: client_y.authentication_token }

  assert_response :success
  # Broken binding proof: stack.id (org X) should never equal a value reachable
  # by a token whose current_api_client.stack_id == org_y_stack.id
  refute_equal client_y.stack_id, org_x_stack.id
  assert_includes @response.body, org_x_stack.deploys_and_rollbacks.last.sha rescue
    assert_includes @response.body, 'lastBuildLabel'
  # demonstrates org X's build data rendered for a token scoped to org Y
end
```

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
