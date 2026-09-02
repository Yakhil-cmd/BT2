### Title
Unauthenticated cross-stack exfiltration of deploy state via `CCMenuController#stack` bypassing token scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` defines its own private `stack` method that resolves `Stack.from_param!(params[:stack_id])` directly against the entire `Stack` table, instead of using the shared, scope-aware `stack`/`stacks` helpers from `BaseController`. As a result, a single legitimately-issued API token with `read:stack` permission tied to one `stack_id` can be replayed against any numeric `stack_id` to read any tenant's CCMenu status (branch, last deploy sha, running state).

### Finding Description
The intended binding, as implemented in `Shipit::Api::BaseController`, is:
`stack ∈ Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true — enforced by: [1](#0-0) 

`CCMenuController` overrides this shared helper with its own version that drops the scoping entirely: [2](#0-1) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains `"read:stack"` — it never checks which stack the token is scoped to: [3](#0-2) 

So for a token created with a fixed `stack_id` (e.g. stack 1) and `permissions: ["read:stack"]`, a request to `GET /api/stacks/2/cc_menu.xml?token=<token>` passes `require_permission!(:read, :stack)` (permission list matches regardless of stack id) and then `stack` resolves `Stack.from_param!(2)` against the unfiltered `Stack` table, returning stack 2's record even though `current_api_client.stack_id == 1`. `#show` then renders `stack.deploys_and_rollbacks.last` for stack 2: [4](#0-3) 

None of the existing guards catch this: `authenticate_api_client` only validates the token signature/existence, not stack ownership; `require_permission!` checks only the permission name; and the correctly-scoped `stacks`/`stack` helpers in `BaseController` are shadowed by CCMenuController's own definition, so the intersection with `current_api_client.stack_id` never executes for this controller.

### Impact Explanation
Any attacker holding a single valid CCMenu-capable API token (with `read:stack` and a fixed `stack_id`) can enumerate sequential/predictable numeric stack ids and retrieve every other tenant's current branch, last deploy SHA, and running/build status through `cc_menu.xml`. This is repeatable indefinitely across the entire `Stack` table with one token, constituting unauthenticated (relative to the target stacks) read of stack state — matching the High severity category "unauthenticated read of stack state."

### Likelihood Explanation
Preconditions are minimal: the attacker only needs one legitimately obtained API token scoped to their own single stack with `read:stack` permission (no special role beyond a normal API client user), and stack ids must be enumerable sequential integers (default Rails primary keys). No secrets (`api_clients_secret`, `secret_key_base`, GitHub tokens) need to be obtained. The attack cost is a simple HTTP GET loop, fully feasible and repeatable.

### Recommendation
Remove the private `stack` override in `CCMenuController` and rely on `BaseController#stack`/`#stacks`, which intersects `Stack.from_param!` results with `Stack.where(id: current_api_client.stack_id)` whenever `current_api_client.stack_id?` is true. Equivalently, add the same scoping check explicitly inside `CCMenuController#stack` before rendering.

### Proof of Concept
```ruby
# test/controllers/shipit/api/ccmenu_controller_test.rb
test "cannot fetch cc_menu.xml for a stack outside the token's scope" do
  own_stack = shipit_stacks(:shipit)
  other_stack = shipit_stacks(:cyclimse) # a different fixture stack

  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "scoped-token",
    stack_id: own_stack.id,
    permissions: ["read:stack"]
  )
  token = scoped_client.authentication_token

  # Sanity: token works for its own stack.
  get "/api/stacks/#{own_stack.id}/cc_menu.xml", params: { token: token }
  assert_response :success

  # Exploit: same token enumerates an unrelated stack.
  get "/api/stacks/#{other_stack.id}/cc_menu.xml", params: { token: token }
  # Binding under test: Stack.find(other_stack.id) ∈ Stack.where(id: scoped_client.stack_id) must be false,
  # so this request must NOT return 200 with valid CCMenu XML for other_stack.
  assert_response :not_found # currently fails: returns 200 with other_stack's deploy data
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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
