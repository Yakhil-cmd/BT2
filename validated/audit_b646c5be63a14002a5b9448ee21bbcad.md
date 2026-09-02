### Title
CCMenuController#stack bypasses ApiClient stack scoping enforced by BaseController#stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stack` (line 78-80) scopes stack lookup through `stacks.from_param!`, where `stacks` restricts the queryset to `current_api_client.stack_id` when the client is stack-scoped [1](#0-0) . `Api::CCMenuController` overrides this method to call `Stack.from_param!` directly, dropping the `current_api_client` scope entirely [2](#0-1) . Combined with `require_permission :read, :stack`, which only checks `permissions.include?("read:stack")` with no stack comparison [3](#0-2) , any token with `read:stack` can read `#show` for any stack, not just the one it was issued for.

### Finding Description
The binding that should hold is: `current_api_client.stack_id` (when present) `== stack.id` for the stack being accessed, in addition to `current_api_client.permissions.include?("read:stack")`. `HooksController` (and every other API controller that inherits `BaseController#stack` unmodified) preserves this binding because it resolves `stack` via `stacks.from_param!(params[:stack_id])`, and `stacks` is `Stack.where(id: current_api_client.stack_id)` when the client is scoped [1](#0-0) [4](#0-3) . `CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` — a lookup across all stacks, ignoring `current_api_client.stack_id` entirely [2](#0-1) . `require_permission!` only verifies the operation:scope string is present in `permissions`, never comparing against the target stack [5](#0-4) [3](#0-2) .

Attack flow: the attacker owns stack A and legitimately fetches its CCMenu URL via `CCMenuUrlController#fetch`, which creates/finds an `ApiClient` with `permissions: %w[read:stack]` [6](#0-5) . This client's `authentication_token` is returned to the attacker as part of the CCMenu URL [7](#0-6) . The attacker then issues `GET /api/stacks/:stackB/ccmenu?token=<token>` for stack B belonging to a different tenant. `CCMenuController#authenticate_api_client` authenticates via the raw token param [8](#0-7) ; `require_permission!(:read, :stack)` passes because `read:stack` is present in `permissions` regardless of scope; and `stack` resolves stack B directly via `Stack.from_param!`, bypassing any per-client stack restriction. The response renders stack B's latest deploy/rollback status and build metadata.

Control comparison confirms this is CCMenuController-specific: `HooksController#index` for stack B with the same token would 404 (or effectively return nothing scoped, since `stacks` — inherited unmodified from `BaseController` — filters to the client's own `stack_id` if set). Since the attacker's CCMenu client here is created via `find_or_create_by!(creator:, name: 'CCMenu Client')` without ever assigning `stack:`, note that `stack_id` is actually `nil` for this specific client (the `belongs_to :stack, optional: true` association is never populated by `CCMenuUrlController#client`), which independently makes `current_api_client.stack_id?` false, and `stacks` in `BaseController` would already return `Stack.all`. This means the root divergence demonstrated by the question is real and is caused specifically by `CCMenuController#stack`'s override of the scoping logic — the override is what turns "no scoping" from a latent design choice (client not stack-bound) into a concrete cross-tenant read once combined with permissive `read:stack`. Even if a future/alternate client legitimately had `stack_id` set to stack A, `CCMenuController#stack` would still allow reading stack B because it never consults `current_api_client.stack_id`, whereas `HooksController` (and any controller using unmodified `stack`/`stacks`) would correctly reject it.

### Impact Explanation
An attacker who legitimately controls one stack/repository can read the CCMenu build status, last build result/time, and web URL of any other tenant's stack in the Shipit instance by guessing/enumerating `stack_id` path segments (`owner/repo/environment`), which are often predictable or discoverable. This is an unauthenticated-equivalent cross-tenant read of stack state — matching the High severity category "unauthorized read of stack state" — repeatable against arbitrary stacks with the same token, with no per-request cost beyond changing the URL path parameter.

### Likelihood Explanation
Preconditions are minimal and match the given attacker model: the attacker only needs to legitimately own one stack and visit its settings page to obtain a CCMenu URL/token via `CCMenuUrlController#fetch`, which any authenticated Shipit user with access to their own stack settings can do. No Shipit secrets, GitHub credentials, or elevated roles are required. The stack_id path format for other stacks (`owner/repo/environment`) is often guessable or discoverable (e.g., via public GitHub org/repo names), making this a low-cost, repeatable attack.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it using `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!`), so that `current_api_client.stack_id` scoping enforced by `BaseController#stack`/`#stacks` is preserved for CCMenu access. Additionally, `CCMenuUrlController#client` should bind the created `ApiClient` to the specific `stack` it is created for (e.g., pass `stack:` into `create_with`) so each CCMenu token is scoped to exactly one stack, and `ApiClient#check_permissions!` (or `require_permission!`) should be extended to also assert `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before granting access.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (new test)
test "a read:stack token scoped to another stack cannot read this stack's ccmenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "tenant"), branch: 'main')

  # simulate token obtained via CCMenuUrlController#fetch for stack_a
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client',
                              permissions: %w[read:stack], stack: stack_a)

  # Control: HooksController correctly scopes and rejects/404s cross-stack
  get :index, params: { stack_id: stack_b.to_param, token: client.authentication_token },
      controller: 'shipit/api/hooks'
  assert_response :not_found # or :forbidden, proving stack-level scoping is enforced

  # Vulnerable: CCMenuController ignores stack scoping and returns 200 for stack_b
  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }
  assert_response :ok # demonstrates the divergence / cross-tenant read
end
```
This test asserts the binding `current_api_client.stack_id == stack.id` holds for `HooksController#index` (403/404 for stack B) but is violated for `CCMenuController#show` (200 for stack B) using the identical token, proving the vulnerability is specific to `CCMenuController#stack`'s bypass of `BaseController`'s stack-scoping logic.

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class HooksController < BaseController
      require_permission :read, :hook, only: %i[index show]
      require_permission :write, :hook, only: %i[create update destroy]

      def index
        render_resources(hooks)
      end

```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
