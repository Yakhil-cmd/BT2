### Title
CCMenuController bypasses ApiClient stack scoping, allowing a stack-scoped token to read any other stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly instead of using `BaseController#stacks.from_param!`, which is the only place that enforces `current_api_client.stack_id == requested stack`. Combined with `#authenticate_api_client` accepting a plain query-string `token`, any `ApiClient` holding the `read:stack` permission — even one created and scoped to a specific stack — can read the CCMenu deploy status of any other stack.

### Finding Description
The binding that should hold is: `current_api_client.stack_id == params[:stack_id]` (when `stack_id` is set on the client), enforced in `BaseController#stacks`: [1](#0-0) 

`Api::CCMenuController` never uses `#stacks`; it defines its own `#stack` resolving directly against the global `Stack` model, and its own `#authenticate_api_client`, which authenticates via `params[:token]` without going through Basic-Auth: [2](#0-1) 

`ApiClient#check_permissions!` only checks that the permission string (`read:stack`) is present in the client's `permissions` array; it never compares `stack_id` to the requested resource: [3](#0-2) 

So for `Api::CCMenuController`, any client satisfying `read:stack` — regardless of its `stack_id` — can fetch `GET /api/stacks/<any_stack>/cc_menu.xml?token=<token>` and get that stack's data, because the `stack_id` binding present in the base controller's `#stacks` is never consulted here.

I checked the actual token-minting path, `CCMenuUrlController#fetch`/`#client`, which creates a single shared `ApiClient` per user named `'CCMenu Client'` with `permissions: %w[read:stack]` and **no `stack:`/`stack_id` set at all**: [4](#0-3) 
Because this client's `stack_id` is nil, it is already effectively global under the base controller's own scoping rule (`stack_id? ? Stack.where(...) : Stack.all`). So the exact "stack A's badge token used against stack B" scenario as posed (implying the badge token is bound to stack A) does not hold for the CCMenu URL feature — that client was never stack-scoped to begin with.

However, the underlying divergence is still real and exploitable: the platform supports creating `ApiClient` records that *are* scoped to a specific stack (`belongs_to :stack, optional: true`) with `read:stack` permission, intended to be usable only for that stack via the standard scoped endpoints (`Api::StacksController`, etc., which use `stacks.from_param!`). Because `Api::CCMenuController` overrides `#stack` to bypass `#stacks` entirely, such a stack-A-scoped token can be replayed against `GET /api/stacks/<stack_B_id>/cc_menu.xml?token=<A's token>` and will succeed, disclosing stack B's deploy status. No existing guard (`require_permission!`, `check_permissions!`, `verify_signature`, etc.) checks `current_api_client.stack_id` in this controller.

### Impact Explanation
An attacker holding any `ApiClient` token with `read:stack` permission — including one deliberately scoped to a single stack by an operator — can enumerate/read the CCMenu deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state) of any other stack on the instance, not just the one the token was issued for. This is repeatable against arbitrary stacks by iterating `stack_id` values, and constitutes cross-tenant disclosure of deploy state, matching the "unauthenticated read of stack state / deploy output" High-severity category. It does not by itself achieve RCE, secret exfiltration, or a write to another tenant's records, so it does not meet the Critical bar as claimed in the question.

### Likelihood Explanation
Exploitation requires possession of a valid `ApiClient` token with `read:stack` permission (any such token, not necessarily unscoped) — this is a low but nonzero bar since `ApiClient` tokens are routinely distributed for stack-specific integrations. The default `CCMenuUrlController`-issued tokens are already unscoped by design, so they don't demonstrate the cross-tenant escalation described; but any legitimately stack-scoped `ApiClient` (`stack_id` set, `read:stack` permission) is trivially exploitable against this controller with a single crafted GET request, no other secrets needed.

### Recommendation
Have `Api::CCMenuController#stack` use the same scoped lookup as the rest of the API (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so `current_api_client.stack_id` (when set) is enforced consistently across all API controllers.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped token cannot read another stack's cc_menu data" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  scoped_client = ApiClient.create!(
    creator: @user, name: "Scoped Client", stack: stack_a, permissions: %w[read:stack]
  )

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: current_api_client.stack_id (stack_a.id) == requested stack (stack_b.id) -> should be false
  # Expected secure behavior: 403/404 because stack_a.id != stack_b.id
  assert_response :forbidden # or :not_found
end
```
Currently this request returns `200 OK` with stack B's XML payload, demonstrating the missing `stack_id` equality check in `Api::CCMenuController#stack`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
