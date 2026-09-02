### Title
Stack-scoped ApiClient token can read the CI/deploy status of *any* stack via the CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor used by `Shipit::Api::BaseController` to resolve the object a request acts on, but it resolves the stack directly from `Stack.from_param!(params[:stack_id])` instead of going through the client-scoped `stacks` collection. This breaks the binding "the stack a token authorizes" (`current_api_client.stack_id`) versus "the stack the request actually touches" (any `stack_id` in the URL), mirroring the `Invoke.invokeTransfer` bug class where a caller performs an authorization-relevant call but never checks that its outcome/target matches what was actually validated.

### Finding Description
In `BaseController`, per-stack read access is meant to be constrained to the stack a token was issued for: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`require_permission :read, :stack` only checks that the client has the `read:stack` permission string in its permission list; it never checks which stack the client is scoped to: [2](#0-1) 

The actual stack-scope enforcement lives entirely in the `stacks`/`stack` helper above. `CCMenuController`, however, redefines `stack` to bypass that helper entirely: [3](#0-2) 

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

`require_permission :read, :stack` still runs and passes (it only checks the permission list), but the object being rendered (`stack.deploys_and_rollbacks.last`) is looked up with no `current_api_client.stack_id` filter at all. This is the analog of the ERC20 bug: a security-relevant check happens (the `read:stack` permission gate / the `invoke` call), but the value/target that check should have been bound to (`current_api_client.stack_id` / the ERC20 transfer's success flag) is silently ignored downstream.

### Impact Explanation
An ApiClient token that a stack owner deliberately scoped to a single stack (e.g. `here_come_the_walrus`, fixture at `test/fixtures/shipit/api_clients.yml:12-17`, scoped to `stack: shipit`, with only `read:stack` permission) can be used to read the CI status, last build label/time, and web URL of any other stack in the Shipit instance by simply changing `stack_id` in the `GET /api/stacks/:stack_id/ccmenu` request (or the equivalent CCTray URL with `?token=`). This is an unauthorized cross-stack read of deploy/build state that the token issuer never intended to grant, matching the High-impact category "unauthenticated/unauthorized read of stack state ... or deploy output" from a token that was supposed to be confined to one stack.

### Likelihood Explanation
Any holder of a stack-scoped, read-only ApiClient token (the least-privileged type of credential Shipit issues) can trigger this with a single unauthenticated-parameter GET request; no write access, no elevated permission, and no additional secrets are required beyond the token itself, which is exactly the class of credential meant to be tightly scoped. The bypass is deterministic and requires no race condition or timing.

### Recommendation
Have `CCMenuController#stack` resolve through the same `stacks` scoping helper used by `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that clients scoped to a specific `stack_id` cannot resolve stacks outside that scope.

### Proof of Concept
1. Create/obtain an ApiClient token scoped to `stack_id: A` with only `read:stack` permission (e.g. fixture `here_come_the_walrus`).
2. Issue `GET /api/stacks/<owner>/<repo-of-stack-B>/<env-of-stack-B>/ccmenu?token=<token-for-A>` where stack B is a different stack the token was never scoped to.
3. Observe `require_permission :read, :stack` passes (only checks the permission list), `CCMenuController#stack` resolves stack B via `Stack.from_param!` (no scope filter), and the response renders stack B's CI/deploy status - which the token holder should not be authorized to view.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
```
