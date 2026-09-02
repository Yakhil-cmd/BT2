## Finding

### Title
API client stack-scope bypass in CCMenu endpoint allows unauthorized read of any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
This engine implements the same class of trust-binding bug as the Wormhole NTT report: a value that is supposed to gate execution (the Transceiver index ordering, verified only at completion time) is not enforced at the point where the privileged action actually happens. In shipit-engine, the analogous binding is: *the stack an `ApiClient` token is scoped/authorized to* versus *the stack the request handler actually touches*. `Api::BaseController` enforces this binding for every API resource by routing all stack lookups through a scoped `stacks` relation, but `Api::CCMenuController` overrides the `stack` accessor and bypasses that scoping entirely.

### Finding Description
`Api::BaseController` defines the authorization binding that every stack-scoped API endpoint is expected to honor: [1](#0-0) 

`stacks` restricts the visible set of stacks to `current_api_client.stack_id` when the client is scoped to one, and `stack` (used by `OutputsController`, `StacksController`, etc.) is derived from that scoped relation. Permission checks are only generic operation/scope checks: [2](#0-1) [3](#0-2) 

`check_permissions!` only verifies the string `"read:stack"` is present in `permissions` — it says nothing about *which* stack. The actual authorization boundary (which stack a token may touch) is enforced solely by the `stacks`/`stack` scoping method in `BaseController`.

`Api::CCMenuController`, however, overrides `stack` to bypass that scoping and resolve the stack directly from unscoped `Stack.from_param!(params[:stack_id])`: [4](#0-3) 

It still declares `require_permission :read, :stack`, which only checks that the token carries the generic `read:stack` permission string — not that the token is scoped to the requested stack. So a token created with `stack_id` set (as in the fixture `here_come_the_walrus`, scoped to stack `shipit`, with permission `read:stack`) is authorized only for that one stack when used against every other stack-scoped controller: [5](#0-4) 

But because `CCMenuController#stack` ignores `current_api_client.stack_id`, that same token can be used with an arbitrary `stack_id` route parameter to fetch the CI/build status (`show` action) of *any* stack in the installation, not just the one it was scoped to.

Binding broken (equality that should hold but doesn't):
`stack authorized by token (current_api_client.stack_id)` == `stack touched by request (CCMenuController#stack)`

Before the request: attacker holds a token whose `stack_id` restricts it to Stack A.
After the request: the same token, sent with `stack_id=B` in the URL, successfully returns Stack B's deploy/CI status — a stack the token was never authorized to read.

### Impact Explanation
This grants unauthenticated/unauthorized read of stack state (last deploy status, label, build time, web URL) for any stack in the Shipit instance using a token that was only supposed to be scoped to one stack. This matches the "High" impact bucket explicitly listed in scope: "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (which is routinely handed out, e.g. via `CCMenuUrlController`, to be embedded in third-party CI dashboard tools) can trivially trigger this by changing the `stack_id` route parameter on the `Api::CCMenuController#show` request. No special privileges beyond possessing one legitimately-scoped token are required, and the request path is a normal, documented API endpoint.

### Recommendation
Have `Api::CCMenuController#stack` resolve through the same scoped `stacks` relation used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!`, so the stack-scope binding enforced elsewhere in the API is also enforced here.

### Proof of Concept
1. Create/obtain an `ApiClient` token scoped to `stack_id` = Stack A, with permission `read:stack` (e.g., via `CCMenuUrlController#fetch`, which mints such scoped tokens for embedding CCMenu URLs).
2. Send `GET /api/stacks/:stack_id_of_B/ccmenu.xml?token=<tokenScopedToA>` where `stack_id_of_B` refers to an unrelated Stack B that the token was never scoped to.
3. Observe the response returns Stack B's `lastBuildStatus`/`lastBuildLabel`/`lastBuildTime`/`webUrl` successfully (HTTP 200), even though `current_api_client.stack_id` corresponds only to Stack A — confirmed by `Api::CCMenuController#stack` at [6](#0-5)  which never consults `current_api_client.stack_id?` before loading the stack, unlike `Api::BaseController#stack`/`#stacks` at [1](#0-0) .

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-22)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
