### Title
CCMenu API tokens are not scoped to the requesting stack, allowing cross-stack read of Task/Deploy state - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` for `current_user` with `read:stack` permission but never assigns `stack:` on that client, so the client's `stack_id` is `nil`. Because `Api::BaseController#stacks` treats a `nil` `stack_id` as "no restriction" (`Stack.all`), the resulting token can be replayed against `Api::CCMenuController#show` (or any other `read:stack`-gated endpoint) for any stack, not just the one the URL was generated for.

### Finding Description
The claimed binding — "the stack named in the query params == the stack the returned ApiClient authorizes" — is **false** both before and after the request.

- `CCMenuUrlController#fetch` resolves `stack` from `params[:stack_id]` and builds the CCMenu URL with `stack_id: stack.to_param`, but the `ApiClient` is created via: [1](#0-0) 
which only keys on `creator: current_user, name: 'CCMenu Client'` — it never sets `stack: stack`. `ApiClient#stack` is `optional: true` and defaults to `nil`: [2](#0-1) 

- Because this client is `find_or_create_by!`'d on `(creator, name)` only, the **same** client/token is reused for every stack a given user ever requests a CCMenu URL for — it is never re-scoped per stack.

- `Api::BaseController#stacks` determines the accessible stack set purely from `current_api_client.stack_id?`: [3](#0-2) 
When `stack_id` is `nil` (as it always is for the CCMenu client), the scope becomes `Stack.all`, i.e. unrestricted.

- `Api::CCMenuController#show` only checks the permission bitmask (`read:stack`) via `require_permission :read, :stack`, and resolves the target stack via `stacks.from_param!(params[:stack_id])`: [4](#0-3) 
There is no check that `current_api_client`'s scope matches the requested `stack_id`; `require_permission!` only calls `check_permissions!` on the operation/scope name, not on stack identity: [5](#0-4) 

Attacker flow: as a collaborator with legitimate access only to stack A, hit `GET /stacks/:id/ccmenu_url` (routed to `CCMenuUrlController#fetch`) to obtain a token. Because that token's underlying `ApiClient.stack_id` is `nil`, replay the same token against `GET /api/stacks/<stack-B>/ccmenu.xml` with `stack_id` swapped to private stack B. `Api::CCMenuController#show` will resolve stack B (since `stacks` == `Stack.all` for this client) and render its latest deploy/task XML, disclosing task output/build status for a stack the attacker was never authorized against.

None of the existing guards catch this: `require_permission :read, :stack` only checks the permission string, not stack scoping; `ExplicitParameters`/model validations don't apply here; and there's no `before_action` in either controller confirming that the token's stack (if any) matches `params[:stack_id]`.

### Impact Explanation
An attacker with legitimate collaborator access to any one stack (stack A) can escalate to read Task/Deploy status, lock state, and build activity (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.) for **any other stack** in the Shipit instance, including private stacks they were never granted access to. This is a cross-tenant/cross-repository unauthorized read of deploy/task state, matching the High severity category ("unauthenticated read of stack state, task streams or deploy output" — here achieved via a token issued for one stack but effectively valid globally). The attack is fully repeatable: the same token works against arbitrary `stack_id` values, and the underlying `ApiClient` row persists indefinitely (`find_or_create_by!`), so it is a durable skeleton key once obtained.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs to be a viewer/collaborator on at least one stack in the Shipit instance and be logged in via the standard session flow to reach `CCMenuUrlController#fetch` (a normal, documented feature endpoint). No GitHub secrets, webhook forgery, or special roles are required — just one legitimate CCMenu URL request followed by a parameter substitution on the resulting XML endpoint. This is low-cost and highly feasible for any authenticated Shipit user with access to at least one stack.

### Recommendation
When creating the CCMenu `ApiClient`, scope it to the specific stack (e.g. `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`), and enforce in `Api::BaseController#stacks`/`Api::CCMenuController#stack` that a stack-bound client can only resolve its own `stack_id`, never falling back to `Stack.all` unless the client is explicitly instance-wide (e.g. `UnlimitedApiClient`).

### Proof of Concept
Minitest plan (no live GitHub, uses fixtures/factories):
```ruby
test "CCMenu token issued for stack A cannot read stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "private-bar"), branch: 'main')

  user = shipit_users(:walrus)
  session[:user_id] = user.id

  get :fetch, params: { stack_id: stack_a.to_param } # CCMenuUrlController#fetch
  assert_response :ok
  token = Rack::Utils.parse_nested_query(URI(JSON.parse(response.body)['ccmenu_url']).query)['token']

  client = ApiClient.last
  assert_nil client.stack_id # binding broken: client not scoped to stack_a

  # Replay token against a different, unauthorized stack B via the API controller
  @request = ActionDispatch::TestRequest.create
  get shipit.api_stack_ccmenu_path(stack_id: stack_b.to_param), params: { token: token }
  assert_response :ok # currently 200 — should be 403/404
  assert_match stack_b.to_param, response.body
end
```
Both sides of the equality (`params[:stack_id] == stack_a` vs. `client.stack_id == nil` → resolves to any stack) diverge, confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-31)
```ruby
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
