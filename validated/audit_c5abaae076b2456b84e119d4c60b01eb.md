### Title
`CCMenuController#stack` bypasses per-client stack scoping enforced by `BaseController#stacks` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` scopes stack lookups to `current_api_client.stack_id` when the client is restricted to a single stack, but `Shipit::Api::CCMenuController#stack` overrides this with an unscoped `Stack.from_param!(params[:stack_id])`, so any `ApiClient` holding the `read:stack` permission can read the CCMenu status of any stack in the installation, not just the one it was scoped to.

### Finding Description
The broken binding: `stack.id ∈ (current_api_client.stack_id? ? [current_api_client.stack_id] : Stack.all.ids)` must hold for every `#show` action reached through `CCMenuController`, matching the invariant enforced by `BaseController#stacks`/`#stack`: [1](#0-0) 

`CCMenuController` instead defines its own `#stack` that never consults `stacks` or `current_api_client.stack_id` at all: [2](#0-1) 

The only check performed before `#show` runs is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(:read, :stack)` — a purely permission-string check that has no notion of *which* stack is authorized: [3](#0-2) [4](#0-3) 

So for any `ApiClient` row with `permissions: ['read:stack']` and a non-nil `stack_id` set (an `ApiClient` `belongs_to :stack, optional: true`, and the admin-facing `ApiClientsController`/`resources :api_clients` route lets an operator create such stack-scoped tokens): [5](#0-4) 
a request `GET /api/stacks/<stack_B>/cc_menu.xml?token=<token_scoped_to_stack_A>` passes `authenticate_api_client` (token verifies), passes `check_permissions!(:read, :stack)` (permission string present regardless of stack), and then `#stack` resolves stack B directly via `Stack.from_param!`, rendering stack B's deploy status to a client that was only ever authorized for stack A.

Separately, `CCMenuUrlController#fetch` (the normal way of minting a CCMenu token from the UI) compounds the problem: it reuses a single `ApiClient` per user via `find_or_create_by!(creator:, name: 'CCMenu Client')` without ever setting `stack_id`, so tokens minted through that flow are already unscoped (`stack_id` is nil) regardless of `CCMenuController`'s bug: [6](#0-5) 
This doesn't invalidate the finding — it shows the scoping is broken from two independent angles, and any stack-scoped `read:stack` token (e.g. one created directly through the admin `ApiClientsController` with an explicit `stack_id`) is still exploitable purely because of `CCMenuController#stack`'s override.

No other guard (`verify_signature`, `force_github_authentication`, `ExplicitParameters`, model validations) applies here — this is a controller-level authorization scoping bug, not an input-validation or signature issue.

### Impact Explanation
A `read:stack`-permissioned API token that was intended to be restricted to one stack (via `ApiClient#stack_id`) can be replayed against `/api/stacks/:stack_id/cc_menu.xml` for any other stack in the Shipit installation, disclosing that stack's latest deploy/rollback status, build activity, and lock state — data belonging to a different repository/tenant. This is repeatable against every stack in the installation with a single valid token and matches the "High — unauthorized/unauthenticated-scope read of stack state" category, since authorization (not authentication) is what fails: the token is valid, but the *stack* it's used against was never authorized.

### Likelihood Explanation
Exploitation requires possession of any single valid `ApiClient` token that has `read:stack` permission — for example a stack-scoped token created via the admin `resources :api_clients` UI for a legitimate integration, or a shared "CCMenu Client" token from `CCMenuUrlController#fetch`. No GitHub secrets, session, or `api_clients_secret` are needed by the attacker beyond that one token they already legitimately hold for their own stack. The attack is a single GET request with a different `stack_id` in the URL, trivially repeatable against every stack ID in the system.

### Recommendation
Remove `CCMenuController`'s private `#stack` override and let it inherit `BaseController#stack` (i.e., `stacks.from_param!(params[:stack_id])`), so the CCMenu action is subject to the same `current_api_client.stack_id` scoping as every other API controller. Additionally, fix `CCMenuUrlController#client` to scope the `find_or_create_by!` lookup (and `stack_id` assignment) per stack, e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)`, so each minted token is bound to the single stack it was issued for.

### Proof of Concept
Minitest integration test under `test/controllers/api/ccmenu_controller_test.rb`:
```ruby
test "a stack-scoped read:stack token cannot read a different stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")
  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "Scoped CCMenu Client",
    stack: stack_a,
    permissions: %w[read:stack]
  )

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: stack_b.id ∈ (scoped_client.stack_id? ? [scoped_client.stack_id] : Stack.all.ids)
  # scoped_client.stack_id == stack_a.id, stack_b.id != stack_a.id => should be rejected
  assert_response :forbidden # or :not_found, per fix
  refute_includes response.body, stack_b.to_param
end
```
Before the fix this test fails: the request returns `200 OK` and renders stack B's CCMenu XML (`assert_payload 'name', stack_b.to_param` would pass), demonstrating cross-stack disclosure.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
