### Title
Stack-scoped API tokens can read CCMenu build status of any stack, not just the stack the token authorizes - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method used by every other API controller, replacing the stack-scoped lookup with a raw, unscoped `Stack.from_param!`. This breaks the binding "the stack a token authorizes == the stack the token can touch."

### Finding Description
Every other controller under `Shipit::Api` inherits `BaseController#stack`, which resolves the target stack through the `stacks` helper: [1](#0-0) 
`stacks` restricts the queryable set to the single stack an `ApiClient` is scoped to when `current_api_client.stack_id?` is true: [2](#0-1) 

`CCMenuController`, however, overrides `stack` to bypass this scope entirely, resolving the stack directly from the request parameter with no reference to `current_api_client`: [3](#0-2) 

The controller's only authorization gate is `require_permission :read, :stack`, which merely checks that the token's `permissions` array contains `"read:stack"` — it does not check which specific stack the token is bound to: [4](#0-3) 

So the equality that should hold — *the stack a token's `stack_id` authorizes* == *the stack the request actually touches* — is broken specifically on this endpoint. A token created with `read:stack` permission and scoped to Stack A (`ApiClient#stack_id == A`) can be replayed against `GET /api/:stack_id/ccmenu` with `stack_id = B`, and `CCMenuController#stack` will happily load and render Stack B's build status.

### Impact Explanation
This is an unauthenticated (relative to the un-scoped stack) read of stack build/deploy state: `#show` exposes `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for any stack in the installation, including stacks the token was never meant to see: [5](#0-4) 
This matches the High-severity category "unauthenticated read of stack state, task streams or deploy output" from an authorization boundary that should have limited the token to a single stack.

### Likelihood Explanation
Any deployment that issues per-stack, `read:stack`-scoped `ApiClient` tokens (the exact pattern the engine's own `CCMenuUrlController` uses to mint a token) is affected. Once such a token exists, exploiting the flaw only requires an HTTP GET against `/api/<other-stack-id>/ccmenu` with `Authorization: Basic <token>` (or `?token=`) — no further privilege is required beyond possessing that one legitimately-scoped, weaker credential. The vulnerable code path is a permanent structural bypass, not a race condition or timing issue, so likelihood is high wherever scoped CCMenu/API tokens are used.

### Recommendation
Remove the `stack` override in `CCMenuController` (or make it delegate to the inherited `stacks.from_param!` scope) so that CCMenu lookups respect `current_api_client.stack_id`, consistent with every other `Shipit::Api` controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. As an authenticated Shipit user, visit stack A's CCMenu URL (`GET /ccmenu/<A>`), which creates/reuses a `read:stack`-permission `ApiClient` associated with the user (per `CCMenuUrlController#client`), yielding a signed `token`.
2. Note: in the shipped `CCMenuUrlController#client` this token is *not* bound to a specific stack (`stack:` is not set on `find_or_create_by!`), but even if it were fixed to be stack-scoped, the bypass below still applies to any stack-scoped `ApiClient` created via `ApiClientsController`/the settings UI with `stack_id` set and `read:stack` permission.
3. Send `GET /api/<B>/ccmenu?token=<token>` where `B` is a different stack than the one the token is scoped/intended for.
4. `CCMenuController#authenticate_api_client` authenticates the token; `require_permission :read, :stack` passes because the token has `read:stack`; `#show` calls `stack` → `Stack.from_param!(params[:stack_id])`, loading stack `B` unconditionally and rendering its build status in the XML response — despite the token never being authorized for stack `B`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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
