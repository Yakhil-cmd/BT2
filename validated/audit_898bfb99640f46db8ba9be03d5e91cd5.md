### Title
Cross-stack CCMenu read via stack-scoped `ApiClient` token accepted for any `stack_id` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` overrides the base controller's stack-scoping logic and resolves the target stack directly from `params[:stack_id]` via `Stack.from_param!`, instead of going through `stacks` (which filters by `current_api_client.stack_id`). Combined with `require_permission!` only checking the permission string and never comparing `current_api_client.stack_id` to the requested stack, a token minted for stack A's `read:stack` permission can be used to read stack B's CCMenu/deploy status.

### Finding Description
The intended binding is: for a stack-scoped `ApiClient`, `current_api_client.stack_id == stack.id` must hold for any stack-level read. In the base controller this is enforced structurally: `stacks` at [1](#0-0)  restricts the queryable relation to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped, and `stack` looks the requested `:stack_id` up only within that relation, raising `RecordNotFound` (404) if it doesn't belong to the client's stack.

`CCMenuController` bypasses this entirely: [2](#0-1) 
`stack` here calls `Stack.from_param!(params[:stack_id])` unscoped by `current_api_client.stack_id`, so any `:stack_id` in the URL is resolved regardless of which stack the token belongs to.

`require_permission :read, :stack` only triggers `require_permission!`, which delegates to `ApiClient#check_permissions!`: [3](#0-2) 
This only checks `permissions.include?('read:stack')` — a global capability flag — and never compares `stack_id`. `authenticate_api_client` is also overridden to accept `params[:token]` via `ApiClient.authenticate`, which just verifies the signed client id, with no stack binding check either: [4](#0-3) .

Exploit flow: attacker obtains (by any legitimate means available to them, e.g. from a public CCMenu URL of stack A, which is designed to be embeddable/unauthenticated-looking per `CcmenuUrlController`) a `read:stack`-scoped token bound to stack A's `ApiClient`. They then request `GET /api/stacks/<stackB_param>/ccmenu.xml?token=<tokenA>`. `authenticate_api_client` succeeds (token verifies), `require_permission!` succeeds (`read:stack` is present), and `stack` resolves stack B unscoped — returning stack B's deploy/rollback status XML, which was never authorized for token A.

### Impact Explanation
The attacker obtains cross-tenant read of another repository's stack deploy state (latest deploy/rollback id, timestamp, running/success/failure) using a token scoped to a different, unrelated stack. This matches the "High - unauthenticated escalation into unauthorized read of stack state" category since a token intended to be scoped to one repository leaks deploy status for arbitrary other stacks. The attack is repeatable against any stack_id the attacker can guess or discover (stack params are typically `owner/repo/env`, often guessable/public), and requires no interaction from the victim stack.

### Likelihood Explanation
The only precondition is possession of any valid, stack-scoped `read:stack` `ApiClient` token — these are routinely created and distributed via `CcmenuUrlController#fetch` for CI badge integration (e.g., embedded in a CI status badge URL that could be observed by others, checked into a config, or otherwise leaked outside of its intended stack). No secrets (`api_clients_secret`, GitHub tokens) are required to be known by the attacker; they only need one legitimately-issued token for any stack. Cost is a single HTTP GET with a substituted `stack_id`.

### Recommendation
Do not override `stack` in `CCMenuController` to bypass scoping; use the base controller's `stacks`/`stack` (i.e., `stacks.from_param!(params[:stack_id])`) so stack-scoped clients can only resolve their own stack. Alternatively, add an explicit check in `authenticate_api_client`/`require_permission!` for this controller: `raise InsufficientPermission unless !@current_api_client.stack_id? || @current_api_client.stack_id == stack.id`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
module Shipit
  module Api
    class CCMenuControllerTest < ActionController::TestCase
      setup do
        @stack_a = shipit_stacks(:shipit)
        @stack_b = shipit_stacks(:cocoaser) # a different stack fixture
        @client_a = ApiClient.create!(
          creator: shipit_users(:walrus),
          name: 'stack-a-client',
          stack: @stack_a,
          permissions: ['read:stack'],
        )
      end

      test "token scoped to stack A cannot read stack B's ccmenu" do
        get :show, params: { stack_id: @stack_b.to_param, token: @client_a.authentication_token }
        # Expected (secure): 403/404, not scoped to stack B
        assert_response :forbidden # or :not_found, depending on chosen fix
        # Current (vulnerable) behavior returns :ok with stack_b's data:
        # assert_response :ok
        # assert_match @stack_b.to_param, response.body
      end
    end
  end
end
```
Both sides of the binding: expected `current_api_client.stack_id (@stack_a.id) == stack.id` should be enforced and fail closed for `@stack_b.id`; current code never performs this comparison, so the request succeeds and leaks `@stack_b`'s deploy state.

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
