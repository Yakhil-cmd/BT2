Found a genuine binding break: `Shipit::Api::CCMenuController` authenticates its API client from a raw `params[:token]` value but then resolves the target `stack` independently by URL parameter, without checking `current_api_client.stack_id` against the requested stack — unlike every other API controller, which resolves stacks exclusively through `BaseController#stacks`/`#stack`, which filters by `current_api_client.stack_id?`.

### Title
CCMenu API token authorizes only itself but is accepted to read any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides `authenticate_api_client` to accept a token via `params[:token]` instead of the standard Basic-Auth flow, and overrides `stack` to resolve `Stack.from_param!(params[:stack_id])` directly, bypassing the `BaseController#stacks` scoping helper that every other stack-scoped endpoint relies on.

### Finding Description
`BaseController#stacks` is the canonical scoping mechanism that enforces the stack a token authorizes equals the stack it touches: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) . All standard controllers (`StacksController`, `TasksController`, `DeploysController`, `LocksController`, `HooksController`) call `stacks.from_param!(params[:id]/:stack_id)`, so a stack-scoped `ApiClient` (created e.g. via `CCMenuUrlController` with `stack_id` set) can only ever resolve stacks within its own `stack_id`.

`CCMenuController`, however, defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` model [2](#0-1) , and its own `authenticate_api_client` that verifies only that the token is a valid, generally-authenticatable `ApiClient` — it never checks `@current_api_client.stack_id` against `params[:stack_id]` [3](#0-2) . The only gate before rendering is `require_permission :read, :stack`, which just checks the client's `permissions` array contains `read:stack` — it says nothing about *which* stack [4](#0-3) .

The binding that should hold is: `token.stack_id (if present) == requested stack_id`. Before the request, this equality holds for every other endpoint. In `CCMenuController`, the equality is never checked, so a CCMenu token minted for stack A (e.g. via `CCMenuUrlController#client`, which explicitly creates a client scoped `permissions: %w[read:stack]` tied to one `stack_id`) can be replayed against any other stack's `/api/stacks/:stack_id/ccmenu.xml` endpoint just by changing the `stack_id` URL segment while keeping the same `token` query parameter.

### Impact Explanation
This is an unauthenticated-for-that-resource read of stack state: deploy status (`lastBuildStatus`), lock status, and build activity for any stack in the Shipit instance, not just the one the token was scoped to — matching the "High: unauthenticated read of stack state" impact bucket. Because `CCMenuUrlController#client` mints such scoped tokens on-demand for any authenticated Shipit user for whichever stack they're viewing [5](#0-4) , any user who can view one stack automatically gets a token that leaks build/lock state of every other stack in the installation, including ones they have no direct access to.

### Likelihood Explanation
Likelihood is high given how easy it is to trigger: any user with access to at least one stack automatically gets a CCMenu token (`GET .../ccmenu_url`), and the attack is a trivial URL parameter substitution (`stack_id`) requiring no additional secrets or signature forgery — the token itself remains valid, only the target resource is switched.

### Recommendation
In `Shipit::Api::CCMenuController#stack`, resolve the stack the same way `BaseController` does elsewhere: scope through `stacks.from_param!(params[:stack_id])` (or explicitly verify `@current_api_client.stack_id.nil? || @current_api_client.stack_id == stack.id`) so that a stack-scoped token cannot be replayed against other stacks.

### Proof of Concept
1. As a legitimate Shipit user with access to `stack_A`, call `GET /stacks/:owner/:repo/:env/ccmenu_url` — this creates/returns an `ApiClient` scoped to `stack_A` with `permissions: ['read:stack']` and its `authentication_token` [6](#0-5) .
2. Take the returned `token` and request `GET /api/stacks/:other_owner/:other_repo/:other_env/ccmenu.xml?token=<token>` for `stack_B`, a stack the attacker has no access to.
3. `authenticate_api_client` succeeds because `ApiClient.authenticate(token)` only verifies the message-signed id, not the stack [3](#0-2) ; `require_permission :read, :stack` passes because the token has the `read:stack` permission string; `stack` resolves `stack_B` unconditionally via `Stack.from_param!` [7](#0-6) . The response leaks `stack_B`'s lock state and last build status/label, which the attacker was never authorized to read.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
