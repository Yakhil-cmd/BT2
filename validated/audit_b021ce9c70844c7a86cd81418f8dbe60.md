### Title
Stack-scoped ApiClient token bypasses stack authorization in `#stack` and reads any stack's CCMenu status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` overrides the inherited, scope-enforcing `#stack` helper from `Api::BaseController` with `Stack.from_param!(params[:stack_id])`, which looks up any stack in the entire table instead of the caller's authorized subset. A token minted with `stack_id: stack_A.id` (scoped, `read:stack` permission) can therefore be used to fetch the CI/deploy status of `stack_B` simply by changing `params[:stack_id]` in the request URL.

### Finding Description
The binding that should hold is: `stack requested via params[:stack_id]` must be a member of `current_api_client`'s authorized set, i.e. `stack.id ∈ (current_api_client.stack_id? ? {current_api_client.stack_id} : Stack.all)`.

`Api::BaseController` implements this correctly via the scoped helper: [1](#0-0) 
`stacks` restricts to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped, and `#stack` looks the requested stack up through that restricted relation via `from_param!`.

`Api::CCMenuController`, however, defines its own `#stack` that bypasses this scoping entirely: [2](#0-1) 
It calls `Stack.from_param!` on the unscoped `Stack` model class directly, not through `stacks`. The `require_permission :read, :stack` before_action only checks that the token has the `read:stack` permission string in its `permissions` array via `ApiClient#check_permissions!`: [3](#0-2) 
— it never checks `current_api_client.stack_id` against the requested stack. So a token with `permissions: ['read:stack']` and `stack_id: stack_A.id` passes `require_permission!(:read, :stack)` regardless of which stack is ultimately loaded by `#stack`, and `#stack` then happily resolves `stack_B` because `Stack.from_param!` is unscoped.

Exploit: attacker obtains (e.g., via a leaked CCMenu URL, which by design embeds `?token=...` in query params — see `authenticate_api_client` override reading `params[:token]`) a token belonging to an ApiClient scoped to `stack_A`. Attacker sends `GET /api/stacks/:stack_B_id/ccmenu?token=<leaked_token>`. `authenticate_api_client` in `CCMenuController` authenticates the client from the token param: [4](#0-3) 
Then `require_permission :read, :stack` passes (client has `read:stack`), and `#stack` resolves `stack_B` unscoped, returning `stack_B`'s deploy/rollback status in the XML response.

None of the listed guards catch this: `verify_signature`/webhook checks are irrelevant (this is a GET, not a webhook); `ExplicitParameters` doesn't validate cross-stack ownership; `require_permission!` only checks the permission string, not `stack_id`; the scoped `stacks` relation that *would* prevent this is simply not used by this controller's local `#stack` override.

### Impact Explanation
An attacker holding a leaked, stack-A-scoped API token can read `stack_B`'s (or any other stack's) latest deploy/rollback status, `ended_at`, and running state for arbitrary other repositories/stacks in the same Shipit instance — an unauthenticated-for-that-resource read of CI/deploy state, matching the "unauthenticated read of stack state" High-severity category. This is repeatable for every stack ID the attacker can enumerate or guess (`Stack.from_param!` typically resolves by numeric id or slug), and the blast radius spans all stacks/tenants managed by the instance, not just the one the token was issued for.

### Likelihood Explanation
Preconditions: attacker must possess a valid `ApiClient` authentication token that is `stack_id`-scoped with `read:stack` permission — CCMenu tokens are commonly distributed as plain URLs (CI dashboard integrations, e.g. CCTray/CCMenu clients), making leakage via browser history, logs, shared dashboards, or copy-pasted links plausible. No GitHub secrets, session, or operator privilege is required; only the leaked token and knowledge/guessing of another stack's `to_param` (id or slug), which is often discoverable (sequential ids, or via the public `/api/stacks` index if the token has broader access, or by observing UI). This is a low-cost, easily repeatable attack once a token is obtained.

### Recommendation
Remove the local `#stack` override in `Api::CCMenuController` and rely on the inherited `Api::BaseController#stack` (which resolves via the scoped `stacks` relation), i.e. delete lines 29–31 of `app/controllers/shipit/api/ccmenu_controller.rb` so `stack` becomes `@stack ||= stacks.from_param!(params[:stack_id])`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (conceptual)
setup do
  @stack_a = shipit_stacks(:shipit)
  @stack_b = shipit_stacks(:cocaine_deploy) # a different stack
  @client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped-client',
    stack_id: @stack_a.id,
    permissions: ['read:stack']
  )
end

test "#show refuses to serve a stack outside the client's scope" do
  assert_equal @stack_a.id, @client.stack_id # binding: authorized stack

  get :show, params: { stack_id: @stack_b.to_param, token: @client.authentication_token }

  # Correct behavior: 404/403, NOT 200 with stack_b's data
  assert_response :not_found
end
```
Currently (pre-fix), this request returns `200 OK` with `stack_b`'s CCMenu XML because `#stack` calls `Stack.from_param!(params[:stack_id])` unscoped, demonstrating the cross-stack read; after applying the recommended fix (using the inherited scoped `stacks.from_param!`), the same request raises `ActiveRecord::RecordNotFound` (rendered as 404), matching the case where `stack_id` is outside the client's authorized set.

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
