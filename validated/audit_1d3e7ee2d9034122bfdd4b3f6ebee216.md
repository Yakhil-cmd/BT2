### Title
CCMenu API endpoint bypasses per-token stack scoping, allowing a stack-scoped API token to read any stack's deploy state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` binds every API operation to the requesting `ApiClient`'s authorized stack set via the `stacks` helper method, which restricts `Stack.where(id: current_api_client.stack_id)` whenever the client is scoped to a single stack. `Shipit::Api::CCMenuController` overrides `#stack` to bypass that scoping entirely, resolving the target stack directly from the unscoped `Stack` relation, breaking the binding "a stack a token authorizes" == "a stack a token can act on."

### Finding Description
`ApiClient` records can be scoped to a single `stack` (`belongs_to :stack, optional: true`), and the base API controller enforces this scope through: [1](#0-0) 

Any controller inheriting `#stack` from `BaseController` (e.g. `StacksController`) can therefore only resolve a stack the token is actually permitted to see. However, `CCMenuController` defines its own `#stack`, which ignores the client-scoping entirely: [2](#0-1) 

`require_permission :read, :stack` (line 6) only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!`: [3](#0-2) 

`check_permissions!` never inspects `current_api_client.stack_id` or compares it against the `stack_id` param — it is a pure string-membership check. Because `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` against the entire `Stack` table rather than the client's `stacks` scope, any token holding `read:stack` (even one explicitly minted for a single stack, e.g. via `CCMenuUrlController#client`) can be replayed against **any other** stack's `stack_id` and successfully render that unrelated stack's CCMenu status.

This mirrors the ERC20 "no return value" bug class: the check that is *supposed* to gate the operation (`stacks` scoping) is silently skipped by an alternate code path (`Stack.from_param!` instead of `stacks.from_param!`), so the token is treated as authorized for a scope it was never actually granted — the binding between "stack a token authorizes" and "stack a token touches" is broken.

### Impact Explanation
This is a High-severity unauthorized read: an attacker holding any valid `read:stack`-scoped API token (e.g. a CCMenu URL token created and handed out for one specific stack, as done by `CCMenuUrlController`) can enumerate and read the deploy state (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock status, etc.) of every other stack in the installation, including ones they have no legitimate access to. This matches the rules' listed High impact: "unauthenticated read of stack state, task streams or deploy output" via a broken token-to-stack authorization binding.

### Likelihood Explanation
Any party who legitimately possesses a stack-scoped API token (such as a CCMenu integration URL, which is designed to be embedded in third-party CI dashboard tools and is not treated as highly sensitive) can trivially exploit this by simply changing the `stack_id` route/query parameter — no additional secrets, signatures, or privileged access are required beyond the token itself, which is exactly the class of credential this scoping mechanism is meant to constrain.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped `stacks` helper (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the per-client stack scope enforced elsewhere in `BaseController` is also honored here.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to Stack A with permission `read:stack`, e.g. via `CCMenuUrlController#client`, which mints `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` bound to Stack A: [4](#0-3) 
2. Note the token via `client.authentication_token`.
3. Call `GET /api/stacks/<STACK_B_ID>/ccmenu.xml?token=<token>` where `STACK_B_ID` is a *different* stack the client is not scoped to.
4. Observe that `CCMenuController#show` renders Stack B's deploy status successfully (HTTP 200 with Stack B's `name`, `lastBuildStatus`, etc.), even though `ApiClient#stack_id` is set to Stack A — demonstrating that the client's stack scope is not enforced on this endpoint.

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
