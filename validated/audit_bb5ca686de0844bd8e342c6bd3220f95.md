## Finding

The bug in the external report is a **verify-then-use binding break**: a value (fee config) that gates a privileged operation is allowed to change between the moment authorization/verification happens and the moment it is actually applied, letting a party retroactively broaden the scope of what a credential/config is allowed to affect. The equivalent binding break that exists in this engine is in `Shipit::Api::CCMenuController`, where the *stack a CCMenu `ApiClient` token is scoped to* diverges from the *stack the request actually touches*.

### Root cause
`Shipit::Api::BaseController` implements the intended enforcement: every stack lookup should go through `stacks`, which is filtered to the `ApiClient`'s own `stack_id` when the client is scoped to one: [1](#0-0) 

`CCMenuController` overrides `stack` to bypass that filter entirely, resolving the stack straight from the request parameter instead of from the scoped `stacks` relation: [2](#0-1) 

The only authorization gate left is `require_permission :read, :stack`, which merely checks that the string `"read:stack"` is present in the token's `permissions` array — it never checks which `stack_id` the token belongs to: [3](#0-2) 

### Why this is the same class of bug
CCMenu tokens are deliberately created scoped to exactly one stack, precisely because they are meant to be embedded in low-trust, often publicly-visible places (build-status dashboards): [4](#0-3) 

So the equality that should hold is: *stack authorized by token* == *stack touched by request*. Before the request: `token.stack_id == A`, and the token is only ever handed out for stack `A`. After the request: due to `CCMenuController#stack` reading `params[:stack_id]` directly, the token can be used to read `stack.deploys_and_rollbacks` for stack `B ≠ A`. The binding that `BaseController#stacks` was designed to enforce is silently dropped by this subclass, exactly analogous to the fee config being applied to already-accrued, previously-authorized rewards.

### Title
Stack-scoped CCMenu `ApiClient` token can read the build status of any stack, not just the stack it was issued for - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from `params[:stack_id]` via `Stack.from_param!`, instead of using the stack-scoped `stacks` relation defined in `Shipit::Api::BaseController`. As a result, an `ApiClient` token that is supposed to be restricted to a single stack (as created by `CCMenuUrlController`) can be replayed against the CCMenu endpoint for any other stack in the Shipit instance.

### Finding Description
`CCMenuUrlController#client` creates (or reuses) an `ApiClient` bound to a specific `stack` with only the `read:stack` permission, and hands its `authentication_token` out embedded in a public CCMenu URL: [5](#0-4) 

`BaseController` enforces stack scoping for such tokens through the `stacks` helper, which restricts the queryable set to `current_api_client.stack_id` when present: [1](#0-0) 

`CCMenuController`, however, overrides `stack` and skips `stacks` entirely, looking the target stack up unscoped from the request parameter: [6](#0-5) 

The remaining `require_permission :read, :stack` check only verifies the presence of the `read:stack` string in `ApiClient#permissions`, with no comparison to `ApiClient#stack_id`: [3](#0-2) 

Thus the equality "stack a token authorizes" == "stack a token touches" is broken exactly at the controller boundary that was supposed to enforce it.

### Impact Explanation
Holding a valid CCMenu token for one stack (a low-privilege artifact, meant for public CI dashboards) is enough to read `stack.deploys_and_rollbacks` (last build status, label, time, web URL) for **any** stack managed by the Shipit instance, including stacks the holder was never granted visibility into. This is an unauthorized read of stack/deploy state across the tenant boundary the token was explicitly scoped to respect — matching the "unauthenticated/under-scoped read of stack state or deploy output" impact class.

### Likelihood Explanation
Exploitation only requires possession of any one legitimate CCMenu URL/token (these are designed to be shared broadly, e.g. pasted into public build-radiators) and changing the `stack_id` segment of the request path to another stack's identifier — no additional secret, session, or elevated permission is needed to escalate from "authorized for stack A" to "read stack B".

### Recommendation
Make `CCMenuController#stack` resolve through the scoped `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])` directly, so that a stack-scoped `ApiClient` can never read data belonging to a different stack, and add an explicit check that `current_api_client.stack.nil? || current_api_client.stack == stack` before rendering.

### Proof of Concept
1. As a legitimate Shipit user, visit `GET /ccmenu/*stack_id` for stack `A` (`CCMenuUrlController#fetch`). Shipit creates an `ApiClient` scoped to `stack_id = A` with `permissions: ["read:stack"]` and returns a URL like `.../api/stacks/A/ccmenu?token=<TOKEN_A>`.
2. Take `TOKEN_A` and request `GET /api/stacks/B/ccmenu?token=<TOKEN_A>` for an unrelated stack `B`.
3. `authenticate_api_client` in `CCMenuController` accepts `TOKEN_A` via `ApiClient.authenticate`. `require_permission :read, :stack` passes because `TOKEN_A` has `"read:stack"`. `stack` resolves `B` directly from `params[:stack_id]`, ignoring that `TOKEN_A.stack_id == A`.
4. The response renders `stack/ccmenu/project` XML with stack `B`'s latest deploy/rollback status, despite `TOKEN_A` never having been authorized for stack `B`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
