### Title
`Api::CCMenuController#stack` bypasses the `ApiClient#stack_id` scope, letting a stack-A-scoped ccmenu token read any stack's status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` scopes stack lookups to the requesting `ApiClient#stack_id` via the `stacks` helper, but `Api::CCMenuController` defines its own private `stack` method that calls `Stack.from_param!` directly, completely skipping that scope check. Any valid ccmenu API token (even one legitimately minted for a specific stack) can therefore be replayed against the `/api/stacks/*stack_id/ccmenu` endpoint of any other stack and successfully retrieve that stack's deploy/build status.

### Finding Description
The binding the system is supposed to enforce is:
`current_api_client.stack_id == requested stack.id` (enforced by `stacks` in `BaseController`).

`BaseController#stacks` implements this: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `BaseController#stack` uses `stacks.from_param!(params[:stack_id])`, i.e. it always looks the requested stack up *through* the scoped relation. [1](#0-0) 

`Api::CCMenuController`, however, overrides `stack` and bypasses that scoped relation entirely, resolving the stack directly from the global `Stack` model: [2](#0-1) 

Authentication for this controller is also overridden to accept a query-string `token` instead of Basic Auth, but it still resolves to a real `ApiClient` via `ApiClient.authenticate`, which does perform valid signature verification: [3](#0-2) [4](#0-3) 

The controller only enforces the generic `read:stack` permission (`require_permission :read, :stack` line 6), never checking whether `current_api_client.stack_id` matches the `stack_id` in the path. Because `stack` is redefined instead of relying on the inherited, scope-checked implementation, any `ApiClient` whose token grants `read:stack` — even one an operator created and scoped to a single stack via `belongs_to :stack` — can be used to fetch CI status XML (`shipit/ccmenu/project` view, including latest deploy/rollback state) for every other stack in the installation by simply changing `stack_id` in the URL.

This is a genuine divergence from the intended scope binding: `stacks.from_param!` (scoped) vs `Stack.from_param!` (unscoped) — the two sides of the equality (`current_api_client.stack_id` vs the path's `stack_id`) are never compared for this controller.

### Impact Explanation
An attacker holding *any* valid ccmenu-capable API token (e.g., one legitimately scoped to their own stack, or one leaked/observed via the URL since it is passed as `params[:token]` in a query string rather than a header) can enumerate and read the deploy/build status of every other stack hosted on the Shipit instance, regardless of the token's intended `stack_id` scope. This is a cross-tenant unauthorized read of stack state, matching the High severity category ("unauthenticated/unauthorized read of stack state"). It does not expose secrets or allow writes, but it does break the tenant isolation the `stack_id` scoping is meant to provide, and is trivially repeatable against arbitrary stacks by iterating over `stack_id` values.

### Likelihood Explanation
The attacker needs one valid ccmenu-capable `ApiClient` token (`read:stack` permission) — these are routinely minted per-stack by `CCMenuUrlController#client` for any logged-in user who visits their stack's settings page, and are transmitted in a URL. No secrets, sessions, or special privileges beyond having access to one stack's ccmenu URL are required. The exploit is a single GET request with the path `stack_id` changed. This is low cost, requires no GitHub secrets, and is fully repeatable.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, scope-checked `stack`/`stacks` methods from `Api::BaseController` so `current_api_client.stack_id` is enforced consistently for the ccmenu endpoint as it is for other API endpoints.

### Proof of Concept
```ruby
test "ccmenu token scoped to stack A cannot read stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # a different stack fixture
  client = ApiClient.create!(creator: shipit_users(:walrus), name: "scoped",
                              stack: stack_a, permissions: %w[read:stack])

  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

  assert_not_equal stack_a.id, stack_b.id
  # Expected (scoped binding enforced): 404/403
  assert_response :not_found
  # Actual today: 200 OK, leaking stack_b's ccmenu status
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end
```
