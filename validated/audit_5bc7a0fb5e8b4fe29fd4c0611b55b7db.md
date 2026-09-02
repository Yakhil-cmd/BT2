## Title
CCMenu API endpoint bypasses `ApiClient#stack_id` scoping, allowing a stack-scoped token to read any stack's build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` restricted to a single stack (`current_api_client.stack_id`) can only resolve `stack`/`stacks` from that stack. `Shipit::Api::CCMenuController` overrides `#stack` to look the stack up directly from `params[:stack_id]` without going through the scoped `stacks` collection, so the binding "the stack a token authorizes" vs "the stack the request actually touches" is broken for this endpoint.

### Finding Description
In the normal API flow, `BaseController` restricts which stacks a client can touch based on the `stack_id` bound to the `ApiClient` record when the request is authenticated: [1](#0-0) 

Every other controller inheriting `BaseController` (e.g. `CommitsController`, `LocksController`, `TasksController`) resolves the target stack through this `stack`/`stacks` helper, so a client whose `stack_id` is set to Stack A can never resolve Stack B.

`CCMenuController`, however, overrides `#stack` to bypass this scoped lookup entirely and resolve the stack straight from the URL parameter: [2](#0-1) 

It also overrides `#authenticate_api_client` to accept the token via a `?token=` query parameter instead of HTTP Basic auth, but still relies on the same global `ApiClient.authenticate` lookup used everywhere else: [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which merely checks that the client's `permissions` array contains `"read:stack"` — a global capability flag, not a per-stack scope check: [4](#0-3) [5](#0-4) 

Because `ApiClient` supports an optional `stack_id` (`belongs_to :stack, optional: true`), any client that was intentionally scoped to one stack (e.g. created with a `stack_id` for restricted CI integration) still authenticates successfully against the CCMenu endpoint, and its request-resolved `stack` is taken from `params[:stack_id]` rather than being filtered by that client's own `stack_id`. This is the exact "signatory not checked" pattern from the report: the token's signature/identity is verified (`ApiClient.authenticate`), but the entity it is scoped to (`stack_id`) is never checked against the entity the request acts on (`params[:stack_id]`).

### Impact Explanation
A stack-scoped `ApiClient` token — intended by an operator to grant read access to a single stack's CI status only — can be replayed against `/api/:stack_id/ccmenu.xml` for any other stack in the Shipit instance. This is unauthenticated (with respect to the target stack) read access to stack build/deploy status, `target_url` and deploy state for stacks the token holder was never authorized to see. This matches the High severity impact category: "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Exploitation only requires possession of any valid `ApiClient` authentication token that has the `read:stack` permission bit and a non-nil `stack_id`, which is a normal, supported way to scope an `ApiClient`. No additional session, elevated privilege, or code execution is required — the attacker only needs to change the `stack_id` URL segment of a request they are already permitted to make against one stack.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection (`stacks.from_param!(params[:stack_id])`) as `BaseController` does, so a client's `stack_id` restriction (when present) is enforced consistently across all API endpoints, including CCMenu.

### Proof of Concept
1. An operator creates (or the application creates, e.g. via `CCMenuUrlController`/API) an `ApiClient` record with `permissions: ["read:stack"]` and `stack_id` set to Stack A only.
2. Using that client's `authentication_token`, issue: `GET /api/<STACK_B_ID>/ccmenu.xml?token=<TOKEN>` where Stack B is a different, unrelated stack.
3. `CCMenuController#authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])`.
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing the `current_api_client.stack_id` filter used elsewhere), returning Stack B.
5. `show` renders Stack B's latest deploy/build status even though the token was only ever authorized for Stack A.

**Note on limitations:** I was unable to confirm through the indexed codebase whether the current web UI (`ApiClientsController#create_params`) exposes a way to set `stack_id` when creating an `ApiClient` from the standard settings page (it only permits `:name` and `permissions`), meaning stack-scoped clients may only be created programmatically/via console/other internal flows. If stack-scoped `ApiClient` records are never created in practice, the practical blast radius of this finding is reduced, though the code-level scoping bypass in `CCMenuController#stack` itself is confirmed and remains a latent trust-boundary violation independent of how such clients are provisioned.

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

**File:** app/models/shipit/api_client.rb (L23-32)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
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
