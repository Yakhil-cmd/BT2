### Title
CCMenu controller bypasses per-stack ApiClient scoping, allowing a stack-scoped token to read any stack's deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` resolves the target stack with an **unscoped** `Stack.from_param!(params[:stack_id])` call, instead of the scoped `stacks.from_param!` helper that every other API controller uses. This breaks the intended binding: *the stack an `ApiClient` token is authorised for* must equal *the stack the request actually operates on*.

### Finding Description
`ApiClient` supports being scoped to a single stack via its optional `stack` association [1](#0-0) . `Api::BaseController` enforces this scoping centrally: the `stacks` method restricts the queryable set to `current_api_client.stack_id` when present, and `stack` resolves the requested record through that restricted relation: [2](#0-1) 

Every controller that inherits this behaviour — `Api::StacksController` (`stacks.from_param!(params[:id])`) and `Api::HooksController` (which derives `stack_id` from `stack`) — is correctly bound: a token scoped to stack A can never touch stack B.

`Api::CCMenuController`, however, overrides `stack` to bypass this restriction entirely: [3](#0-2) 

It authenticates the token (`ApiClient.authenticate(params[:token])`) and checks only the coarse `read:stack` permission flag via `require_permission :read, :stack` [4](#0-3) , which only verifies the permission string is present on the client, not which stack it is scoped to: [5](#0-4) 

Because `stack` in `CCMenuController` never consults `current_api_client.stack_id`, the equality that must hold — `current_api_client.stack_id == requested_stack.id` (or `current_api_client.stack_id.nil?`) — is never checked in this controller, even though it is checked everywhere else in the same namespace.

### Impact Explanation
An `ApiClient` intentionally scoped to a single stack (e.g., a CI credential meant to monitor only `stack_a`'s deploy state) can be replayed against `/api/stacks/*stack_id/ccmenu?token=...` for any other stack in the installation, disclosing that stack's latest deploy/rollback status, build result, and web URL (`shipit/ccmenu/project` template output) — an unauthorized cross-stack read of deploy state via a token that should not have visibility into it. This matches the "High — unauthenticated/unauthorized read of stack state" impact class: the token is valid but its stack-scoping is not honoured for this endpoint, exactly the sherlock report's pattern of an incomplete boundary check letting an edge case slip through the validation logic.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` token can trigger this with a single GET request; no additional privilege, signature, or race condition is required — only knowledge or enumeration of another stack's identifier (owner/repo/environment), which is not treated as a secret elsewhere in the app (stack params appear in URLs throughout the UI).

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped resolution used elsewhere in the namespace:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the private `stack` override so the inherited, scoped `BaseController#stack` implementation is used, restoring the `current_api_client.stack_id == stack.id` binding.

### Proof of Concept
1. An `ApiClient` is created (e.g. via console/administrative tooling) scoped to `stack_a`: `ApiClient.create!(creator: user, name: 'ci', permissions: %w[read:stack], stack: stack_a)`.
2. The resulting `authentication_token` is distributed to a CI dashboard intended to poll only `stack_a`.
3. An attacker in possession of that token issues:
   `GET /api/stacks/other-owner/other-repo/production/ccmenu?token=<token>`
4. `authenticate_api_client` succeeds (token is valid) [6](#0-5) ; `require_permission :read, :stack` passes because the permission list contains `read:stack` regardless of stack [5](#0-4) .
5. `stack` resolves `stack_b` (any stack, unscoped) via `Stack.from_param!`, and its CCMenu XML — including latest deploy status — is rendered and returned to the attacker, even though the token was never authorised for `stack_b`.

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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
