### Title
CCMenu API endpoint lets a stack-scoped `ApiClient` token read the CCTray status of *any* stack, not just the stack it was authorized for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides `#stack` to resolve `params[:stack_id]` directly against `Stack.from_param!`, bypassing the tenant-scoping logic (`stacks`) that every other API controller relies on. An `ApiClient` token that is scoped to a single stack (`api_client.stack_id` set) is meant to only ever "touch" that one stack, but this controller lets it read `deploys_and_rollbacks` build/status information for **any** stack in the installation.

### Finding Description
Every other API controller inherits `Api::BaseController#stack`, which is deliberately scoped to the calling `ApiClient`'s authorized stack: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This is the binding the whole API authorization model relies on: **the set of stacks a token is authorized to touch equals `current_api_client.stack_id`'s stack (or all stacks, for unscoped clients)**.

`CCMenuController`, however, defines its own `#stack` that skips this scoping entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`require_permission :read, :stack` only checks that the authenticated `ApiClient` has the `read:stack` permission string on its `permissions` array; it never checks that the client's `stack_id` (if any) matches the `stack_id` param being requested: [3](#0-2) 

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
  end
  true
end
```

So the equality that should hold - `stack requested == stack authorized by token` - is broken specifically in this controller: the token's authorization is scoped to one stack, but the actual object acted on (`Stack.from_param!(params[:stack_id])`) is any stack the caller names in the URL.

### Impact Explanation
An `ApiClient` created and deliberately scoped to a single stack (e.g. `here_come_the_walrus` fixture, `stack: shipit`, see `test/fixtures/shipit/api_clients.yml`) is supposed to be an unprivileged, narrowly-scoped credential - exactly the kind of "handler with limited privileges" the external report calls for. Because of this controller's bypass, holding that narrowly-scoped token is sufficient to read the CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, lock status, etc.) of every stack in the Shipit installation, including stacks belonging to unrelated repositories/teams the token was never granted access to. This is an unauthorized cross-stack read of deploy/task state, which matches the "unauthenticated read of stack state ... deploy output" High-impact category since the credential's authorization scope is bypassed for this specific endpoint.

### Likelihood Explanation
Any party that legitimately holds one scoped `ApiClient` token (a normal, expected credential-holding actor, e.g. a CI tool integration) can trivially exploit this by supplying a different `stack_id` in the request path/query - no additional secrets, session, or privilege escalation is required beyond what they already legitimately possess. The bug is a straightforward method override that omits the `stacks` scoping helper used everywhere else, so it is deterministic and always reachable via `GET /api/:stack_id/cc.xml?token=...`.

### Recommendation
Remove the custom `#stack` override in `CCMenuController` (or make it call the inherited, scoped `stacks.from_param!` helper) so that a stack-scoped `ApiClient` can only render CCTray XML for the stack it was actually authorized for:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_a` with `permissions: ['read:stack']` and an authentication token.
2. Send `GET /api/stack_b/cc.xml?token=<stack_a's token>` where `stack_b` is a different, unrelated stack.
3. `authenticate_api_client` succeeds (the token is valid), `require_permission :read, :stack` succeeds (the client has `read:stack` in its `permissions`), and `stack` resolves `stack_b` directly via `Stack.from_param!`, returning `stack_b`'s deploy/build status - even though the token's `stack_id` is `stack_a`.

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
