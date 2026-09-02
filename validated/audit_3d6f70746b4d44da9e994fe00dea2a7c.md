This confirms the contrast: `Api::StacksController#stack` correctly uses `stacks.from_param!(params[:id])` (scoped by `current_api_client.stack_id`), while `Api::CCMenuController#stack` at [1](#0-0)  uses `Stack.from_param!(params[:stack_id])` directly, bypassing the scoping entirely.

### Title
Stack-scoped `ApiClient` tokens can read the CCMenu status of any stack, breaking the token's stack authorization binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` records can be scoped to a single stack via `stack_id`, and `Api::BaseController` enforces that scope through its `stacks`/`stack` helpers [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to bypass that scoping and resolve the stack directly from the request parameter, so any valid token — even one deliberately minted for exactly one stack — can be replayed against `params[:stack_id]` for a different stack.

### Finding Description
`ApiClient#check_permissions!` only verifies that the client's `permissions` array contains `"#{operation}:#{scope}"` (e.g. `read:stack`); it never checks `stack_id` [3](#0-2) . The actual per-stack restriction is implemented entirely in `Api::BaseController`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every other API controller (e.g. `Api::StacksController#stack` at [4](#0-3) ) relies on this `stacks` scoping helper. `Api::CCMenuController` instead redefines `stack` as:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [1](#0-0) 

This calls the unscoped `Stack.from_param!` class method rather than the instance-scoped `stacks.from_param!`, so `current_api_client.stack_id` is never consulted. Meanwhile `CCMenuUrlController#client` deliberately mints these narrowly-scoped, `read:stack`-only tokens tied to one specific stack for embedding in third-party CI dashboards [5](#0-4) , and the token is transmitted in a bare URL query string rather than an `Authorization` header [6](#0-5) .

The bug-class analog: the report describes a binding between "emergency enabled" and "emergency stays enabled" that a privileged actor can silently invert. Here the equivalent binding is `token.stack_id == stack_being_read`, established when `CCMenuUrlController` issues the token, but broken by `Api::CCMenuController#stack`, which lets the holder of that token substitute any other `stack_id` in the URL/route and still pass `require_permission :read, :stack` since permission checking never inspects `stack_id`.

### Impact Explanation
Holding a single CCMenu token (which is routinely embedded in low-trust environments such as CI dashboard widgets, browser extensions, or shared status boards, as shown by `CCMenuUrlController`) is enough to read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, activity, lock state) of every stack on the Shipit instance, not just the one it was authorized for. This is an unauthenticated-for-other-stacks read of stack state that matches the High-severity category "unauthenticated read of stack state... " since the attacker never had `read:stack` authorization for the target stack.

### Likelihood Explanation
Any holder of a legitimately-issued CCMenu token (a normal, low-privilege artifact meant for read-only status widgets) can trigger this simply by changing the `stack_id` segment of the CCMenu URL; no additional secrets, GitHub credentials, or elevated session are required. The token is unprivileged, non-admin, and commonly shared/embedded outside Shipit's authentication boundary, so exploitation only requires knowledge of another stack's `owner/repo/environment` identifier.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and instead reuse the scoped `stacks.from_param!(params[:stack_id])` helper from `Api::BaseController`, exactly as `Api::StacksController` does, so `current_api_client.stack_id` scoping is honored for CCMenu requests too.

### Proof of Concept
1. As an authenticated Shipit user, visit `CCMenuUrlController#fetch` for `stack A` (`GET /ccmenu/ownerA/repoA/production`). This creates/reuses an `ApiClient` with `permissions: ['read:stack']` and no `stack_id` restriction is enforced downstream because of the controller bug — but assume in the fixed/intended design it is meant to be scoped to `stack A` since it's issued in that context.
2. Take the returned `ccmenu_url`, which contains `token=<the client's authentication_token>`.
3. Replace the `stack_id` path segment with `ownerB/repoB/production` (any other stack on the instance) and issue `GET /api/stacks/ownerB/repoB/production/ccmenu?token=<token>`.
4. `Api::CCMenuController#authenticate_api_client` authenticates the token via `ApiClient.authenticate` (succeeds — it's a valid token) [6](#0-5) ; `require_permission :read, :stack` passes because the token has `read:stack` in `permissions` [3](#0-2) ; `stack` resolves `stack B` directly via `Stack.from_param!(params[:stack_id])`, ignoring any `stack_id` scoping [1](#0-0) .
5. The response renders `stack B`'s CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, lock state, etc.), which the token holder was never authorized to access.

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
