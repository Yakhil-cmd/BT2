### Title
Stack-scoped API tokens can read CCMenu status of any stack, bypassing the token's stack authorization - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and `Shipit::Api::BaseController` enforces that scope by resolving stacks through the `stacks`/`stack` helper methods. `CCMenuController`, however, overrides `stack` to look the target stack up directly via `Stack.from_param!`, completely bypassing the `stack_id` scoping check, so a token authorized for one stack can read the build/deploy state of any stack.

### Finding Description
`Shipit::Api::BaseController` defines the stack-scoping binding that every API endpoint is supposed to honor: [1](#0-0) 

`stacks` restricts visible stacks to `current_api_client.stack_id` when the token is scoped to a stack, and `stack` resolves `params[:stack_id]` only from within that authorized set. This is the binding: "a stack a token authorises" (`current_api_client.stack_id`) must equal "a stack it touches" (`params[:stack_id]` resolved via `stack`).

`Shipit::Api::CCMenuController` breaks this binding by redefining `stack` to bypass the scoped `stacks` collection entirely: [2](#0-1) 

The controller only checks the coarse `read:stack` permission via `require_permission :read, :stack` (which validates the operation:scope pair, not which specific stack the token is bound to): [3](#0-2) 

So any client holding `read:stack` — including a client created and scoped to one specific stack — can supply an arbitrary `stack_id` param and read that other stack's data. This is also reachable via the query-string-token authentication path this controller supports (`authenticate_api_client` override), which is specifically designed for third-party/unauthenticated CI dashboard consumers: [4](#0-3) 

This class of token is minted per-stack by `CCMenuUrlController`, which is intended to hand out a scoped, unauthenticated URL to a single stack's status: [5](#0-4) 

Before/after the flaw:
- Before: token minted with `stack: X` (or any client with `stack_id` set) → `stack` in the base controller returns X only for any `stack_id` param, because `stacks` filters to `Stack.where(id: current_api_client.stack_id)`.
- After (`CCMenuController#show`): `stack` ignores the client's `stack_id` and returns whatever `Stack.from_param!(params[:stack_id])` resolves to, i.e., any stack in the installation, including private/unrelated stacks.

### Impact Explanation
This allows unauthenticated/low-privilege disclosure of another stack's deploy/rollback status (last deploy id, status, lock state) that the token holder was never authorized to see — matching the "High - unauthenticated read of stack state, task streams or deploy output" impact class, since the CCMenu URL mechanism is explicitly designed to be embedded/queried without full API authentication.

### Likelihood Explanation
Exploitation only requires possession of any valid CCMenu token (which is routinely shared with third-party CI dashboard tools and exposed via URLs, per `CCMenuUrlController`) and knowledge/guessing of another stack's `repo_owner/repo_name/environment` param. No write access, no GitHub credentials, and no privileged Shipit account are required.

### Recommendation
Remove the `stack`/`authenticate_api_client` overrides in `CCMenuController` that bypass scope enforcement, or explicitly re-apply the `current_api_client.stack_id` check when resolving `params[:stack_id]`, e.g., use `stacks.from_param!(params[:stack_id])` from `BaseController` instead of `Stack.from_param!`.

### Proof of Concept
1. As a normal Shipit user, visit `CCMenuUrlController#fetch` for `Stack A` to obtain a scoped token (`ApiClient` with `stack_id = A.id`, permissions `['read:stack']`).
2. Send `GET /api/stacks/:owner/:repo_b/:env/ccmenu.xml?token=<token-for-stack-A>` where `owner/repo_b/env` identifies unrelated `Stack B`.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`, the request succeeds and returns `Stack B`'s build/deploy status, even though the token was only authorized (`stack_id`) for `Stack A`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
