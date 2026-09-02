### Title
CCMenu token minted for one stack authorizes `read:stack` on every stack in the installation - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` mints a long‑lived `ApiClient` token with `read:stack` permission but never binds it to the requested stack, leaving `stack_id` `nil`. That token is consumed by `Api::CCMenuController#show`, whose own private `stack` method resolves the target via `Stack.from_param!(params[:stack_id])` directly instead of the tenant‑scoped `stacks` helper from `Api::BaseController`, so the token can be replayed against `params[:stack_id]` for any stack in the installation.

### Finding Description
The broken binding is: `current_api_client.stack_id` (minted for stack A) **should equal** the `id` of the stack being served, but the observed value is `nil` and the served stack is attacker‑chosen `params[:stack_id]`.

- `CCMenuUrlController#client` does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, scoped only on `creator` and `name`, so `stack:` is never set on create and `stack_id` stays `nil` [1](#0-0) .
- `Api::BaseController#stacks` is meant to enforce tenancy: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [2](#0-1) . With `stack_id` nil, this degrades to `Stack.all`.
- Critically, `Api::CCMenuController` never uses this scoped helper at all: it overrides `stack` with its own `Stack.from_param!(params[:stack_id])`, bypassing `stacks` entirely [3](#0-2) . `require_permission :read, :stack` only checks that the token has the `read:stack` string in its `permissions` array via `ApiClient#check_permissions!`, with no per‑stack check [4](#0-3) .

Exploit flow: an authenticated (unprivileged) Shipit user with only read access to stack A calls `GET /stacks/:stack_id/ccmenu_url` for stack A, receiving `{ccmenu_url: ".../api/stacks/A/ccmenu?token=T"}`. Because `T` is bound to no stack, the attacker replays it as `GET /api/stacks/B/ccmenu?token=T` for any other stack `B` (any org/repo) and `Api::CCMenuController#show` renders stack B's build status/name/lock state, satisfying `require_permission!(:read, :stack)` since the check is permission‑string only, not stack‑scoped, and further bypassing even that intended per‑stack restriction because `stack` never consults `stacks`.

### Impact Explanation
An unprivileged user obtains a single legitimately‑issued CCMenu token and can use it to read stack metadata (name, last build status/label/time, lock status, web URL) for every stack across every tenant/org managed by the Shipit instance, not just the stack they requested the URL for. This is a cross‑tenant unauthorized read of stack state, matching the High severity category "unauthenticated/unauthorized read of stack state, task streams or deploy output" via `Api::CCMenuController#show` [5](#0-4) . It is fully repeatable (the token doesn't expire and can be reused against arbitrary `stack_id` values) and scales to the entire installation's stack inventory.

### Likelihood Explanation
Preconditions are minimal: any user with a Shipit session and access to at least one stack (to trigger `fetch`) can mint the token; no GitHub App secrets, `api_clients_secret`, or operator privileges are needed beyond a normal login. The attacker only needs to enumerate/guess other stacks' `to_param` (owner/repo/branch or slug), which is discoverable information in a typical Shipit deployment. This makes the attack cheap, deterministic, and repeatable.

### Recommendation
Bind the minted `ApiClient` to the requested stack (e.g. `find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`) and fix `Api::CCMenuController#show` to use the tenant‑scoped `stacks.from_param!(params[:stack_id])` (inherited from `Api::BaseController`) instead of its own unscoped `Stack.from_param!`, so a client's `stack_id` binding is actually enforced.

### Proof of Concept
```ruby
test "ccmenu token minted for stack A can read stack B" do
  stack_a = shipit_stacks(:shipit) # org repo-a
  stack_b = Stack.create!(repository: Repository.new(owner: "other-org", name: "repo-b"), branch: "main")

  sign_in(shipit_users(:walrus)) # unprivileged user with access only to stack_a
  get :fetch, params: { stack_id: stack_a.to_param } # ShipitController#fetch
  token = JSON.parse(response.body)['ccmenu_url'][/token=([^&]+)/, 1]

  client = ApiClient.find_by(name: 'CCMenu Client')
  assert_nil client.stack_id # binding broken: stack_id should == stack_a.id

  get "/api/stacks/#{stack_b.to_param}/ccmenu", params: { token: token }
  assert_response :ok # should be 403/404, proving cross-tenant read
end
```

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
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
