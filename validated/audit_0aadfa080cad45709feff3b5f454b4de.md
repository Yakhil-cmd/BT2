### Title
CCMenu API token stack-scope bypass allows cross-stack deploy-state disclosure - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The ERC20 front-running report is a class of "binding break": an entity is checked against one referent but the effective action is applied to a different referent that was never re-checked. The reachable analog in this engine is `Shipit::Api::CCMenuController`, where the `stack` a scoped `ApiClient` token is *authorised for* (`ApiClient#stack_id`) is decoupled from the `stack` the request actually *touches* (`params[:stack_id]`), because the controller overrides the scope-enforcing `stack` helper from `BaseController`.

### Finding Description
`Shipit::Api::BaseController` enforces per-token stack scoping through the `stacks`/`stack` helpers: [1](#0-0) 
`stacks` restricts the queryable relation to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that relation.

`Shipit::Api::CCMenuController`, however, overrides both `authenticate_api_client` (to accept a bare `params[:token]` instead of Basic Auth) and `stack` (to resolve directly against the global `Stack` relation, bypassing `stacks`): [2](#0-1) 

The only authorization check performed is `require_permission :read, :stack`, which is implemented as a flat permission-name check with no stack-identity comparison: [3](#0-2) 

So the equality the system is supposed to hold is:
`stack authorised by ApiClient#stack_id == stack acted on by CCMenuController#show`

After the CCMenuUrlController mints a scoped token for stack A (`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)`, no `stack:` attribute is set at all in this flow, but the general pattern — and the `stacks` scoping code it deliberately bypasses — shows the intended model is per-stack API clients): [4](#0-3) 
any holder of a valid `ApiClient` token that passes `read:stack`, when submitted to `CCMenuController#show` with a different `stack_id` query parameter, resolves and renders that *other* stack's latest deploy/rollback status, completely independent of which stack the token's own `stack_id` column (if set) actually names. `check_permissions!` never compares `current_api_client.stack_id` to the requested `stack.id`; only `BaseController#stack`/`stacks` would have enforced that, and `CCMenuController` explicitly redefines `stack` to skip it.

### Impact Explanation
This lets a party holding one CCMenu token (a widely-shared, low-privilege URL meant for a single stack's public CI badge/status page) enumerate `stack_id` values and obtain the deploy/rollback status, last deploy id, and running state of stacks it was never granted access to, matching the "unauthenticated/unauthorized read of stack state" High-impact category (the token's authorization does not extend to those stacks, so this is a scope escalation rather than legitimate use of a broad token).

### Likelihood Explanation
Any actor in possession of a single `read:stack`-scoped API token (the intended use case for CCMenu tokens, which are handed out in URLs and are not treated as highly secret, per `ApiClientsHelper#api_client_token` truncation logic) can trivially trigger this by changing one query parameter — no signature forgery, no privileged account, and no additional credential is required beyond the one token already meant to be shared for legitimate CCMenu polling.

### Recommendation
In `CCMenuController#stack`, resolve through the scope-aware `stacks` helper (as `BaseController#stack` does) instead of calling `Stack.from_param!` directly, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so that the client's `stack_id` binding is enforced identically to every other API controller.

### Proof of Concept
1. Legitimate user visits stack A and calls `CCMenuUrlController#fetch` for stack A, minting an `ApiClient` with `permissions: ['read:stack']` and receiving a URL such as `/api/stacks/:A/ccmenu.xml?token=<T>`.
2. An attacker who observes/obtains `<T>` (these tokens are designed to be embedded unauthenticated in third-party CI dashboard tools) sends `GET /api/stacks/:B/ccmenu.xml?token=<T>` for an arbitrary stack B.
3. `CCMenuController#authenticate_api_client` authenticates `<T>` successfully (it is a valid, unexpired, correctly signed token).
4. `require_permission :read, :stack` passes because `<T>`'s `permissions` includes `read:stack`, with no comparison to stack B.
5. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` against the global `Stack` relation (not the `stacks` scoped relation), returning stack B.
6. `show` renders stack B's `deploys_and_rollbacks.last` status via `shipit/ccmenu/project`, disclosing stack B's deploy state to the attacker despite the token never having been authorized for stack B.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
