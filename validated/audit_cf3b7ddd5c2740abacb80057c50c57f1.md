This confirms the vulnerability. `CCMenuController#stack` at `app/controllers/shipit/api/ccmenu_controller.rb:29-31` overrides the base implementation and calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, bypassing the `stacks` scoping method defined in `app/controllers/shipit/api/base_controller.rb:74-80` that restricts a stack-scoped `ApiClient` to `Stack.where(id: current_api_client.stack_id)`.I have enough to finalize. The `CCMenuController` finding fits the "stack a token authorises versus a stack it touches" binding: `check_permissions!` only verifies the `read:stack` operation string, never the specific stack ID, and the base `stacks`/`stack` scoping (which does enforce that binding) is bypassed by CCMenu's override.### Title
Stack-scoped API token can read any stack's CI status via CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor to look up the target stack directly from the unscoped `Stack` model instead of going through the `stacks` helper that enforces the binding between an `ApiClient`'s authorized stack and the stack it may touch. This lets any authenticated `ApiClient` — even one scoped to a single stack — read deploy/rollback status for any other stack in the installation by supplying a different `stack_id`.

### Finding Description
`Shipit::Api::BaseController` defines the trust boundary that is supposed to bind an `ApiClient` token to the stack(s) it is permitted to act on: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` (used by every other API controller, e.g. `StacksController`, `HooksController`) resolves `params[:stack_id]` through that scoped relation, so a scoped client can never resolve a stack it doesn't own.

`CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` class rather than `stacks.from_param!(...)`. The only authorization check performed is `require_permission :read, :stack` at the class level: [3](#0-2) 

which resolves to `ApiClient#check_permissions!`: [4](#0-3) 

This check only verifies that the string `"read:stack"` is present in the client's `permissions` array — it never inspects `current_api_client.stack_id` or compares it against the requested `params[:stack_id]`. The equality that should hold is:

`current_api_client.stack_id (the stack the token authorizes) == stack resolved for the request (the stack the controller touches)`

In `BaseController#stack` this equality is enforced by scoping through `stacks`. In `CCMenuController#stack` it is not enforced at all — any stack ID resolves, regardless of the token's `stack_id`.

`CCMenuController` also independently overrides `authenticate_api_client` to accept a token via `params[:token]` (in addition to Basic Auth), so the endpoint is directly reachable with just a valid, possibly narrowly-scoped, `ApiClient` token: [5](#0-4) 

### Impact Explanation
An `ApiClient` created and scoped to a single stack (e.g. a low-privilege CI status widget token, as seeded in fixtures: `here_come_the_walrus` with `stack: shipit`) is intended to only ever see data for that one stack — this is exactly the pattern enforced elsewhere in the API (see `StacksControllerTest#index returns a list of stacks filtered by repo and api client`, which asserts a stack-scoped client sees zero stacks outside its scope). Via `CCMenuController#show`, that same token can retrieve `deploys_and_rollbacks.last` (last build status, label, time, activity) for any other stack in the Shipit instance simply by passing a different `stack_id`, achieving unauthorized cross-stack read of deploy/task state. This matches the "High" impact category: unauthenticated/under-authorized read of stack state.

### Likelihood Explanation
High. Exploitation requires only a valid `ApiClient` token with `read:stack` permission (which is the default/minimal permission most integrations are granted) and knowledge or guessing of another stack's `stack_id` param (a small integer or slug), both of which are trivially obtainable by any party already holding one legitimate scoped token.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped `stacks` relation from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the client's `stack_id` scope is enforced consistently with the rest of the API.

### Proof of Concept
1. Create two stacks, `stack_a` and `stack_b`.
2. Create an `ApiClient` scoped to `stack_a` (`stack_id: stack_a.id`) with `permissions: ['read:stack']`, and obtain its `authentication_token`.
3. As this client, request `GET /api/stacks/:stack_b_id/ccmenu` (or the equivalent CCMenu route) passing `token=<stack_a's token>` and `stack_id` referencing `stack_b`.
4. Observe the response renders `stack_b`'s deploy/rollback status (`shipit/ccmenu/project` XML) even though the token is scoped only to `stack_a` — contrast with the same request against `StacksController#show` for `stack_b`, which correctly returns nothing/404 for a scoped client outside its `stacks` relation.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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
