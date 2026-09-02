### Title
Stack-scoped API tokens can read the deploy status of *any* stack via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` authenticates a stack-scoped `ApiClient` token but never re-applies that client's stack scope when resolving the target `stack`. It overrides the base controller's scoped `stack` accessor with an unscoped lookup, so a token that is only supposed to authorize reads for one stack can be replayed with a different `stack_id` to read another stack's deploy status.

### Finding Description
`Shipit::Api::BaseController` establishes the binding: `stacks a token authorises` == `stacks a request may touch`, implemented as: [1](#0-0) 

`stacks` is scoped down to `current_api_client.stack_id` when the client is stack-scoped, and `stack` is derived from that scoped relation via `from_param!`. `require_permission :read, :stack` only calls `current_api_client.check_permissions!(operation, scope)`, which checks the client's permission list, not which stack it's tied to: [2](#0-1) 

`CCMenuController`, however, defines its own `authenticate_api_client` (auth via a `token` query param instead of Basic Auth) and its own `stack` method that bypasses `stacks` entirely, resolving directly against the whole `Stack` table: [3](#0-2) 

Because `stack` no longer flows through `current_api_client.stack_id`-scoped `stacks`, the `require_permission :read, :stack` check (which only verifies the `read:stack` permission string is present, per `ApiClient#check_permissions!`) passes for a client scoped to Stack A even when the request supplies Stack B's `stack_id`. This breaks the intended equality `token.stack_id == stack.id` for this endpoint: the token *authorises* reads only for the stack it was created against, but the endpoint lets it *touch* (read status of) any stack in the installation, exactly the class of trust-binding failure highlighted in the report (a permission computed for one entity being silently applied to a different, unintended entity).

### Impact Explanation
This is an unauthenticated-scope-bypass style issue: a valid, narrowly-scoped API token (created by a repository owner intending to expose only their own stack's build/deploy status to, e.g., a CI dashboard widget) can be used to enumerate and read the CCMenu XML (deploy status, latest activity, project name) of every other stack managed by the Shipit instance, not just the one it was issued for. This matches the allowed High-impact category "unauthenticated read of stack state ... deploy output" in the sense that read access is obtained outside the token's authorized scope.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped API clients (a documented, supported feature — see `here_come_the_walrus` fixture scoped to a single stack) and exposes CCMenu tokens to less-trusted consumers (CI dashboard tools, status widgets). Exploitation only requires knowing/guessing another stack's `repo_owner/repo_name/environment` param — no additional privilege is required, since the attacker already possesses a legitimately-issued token.

### Recommendation
In `Shipit::Api::CCMenuController`, resolve `stack` through the same client-scoped relation used elsewhere (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) instead of calling `Stack.from_param!` unscoped, so a stack-scoped token can only ever resolve to the stack it was issued for.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack: stack_A` with permission `read:stack` (as shown in `test/fixtures/shipit/api_clients.yml`'s `here_come_the_walrus` fixture) and note its `authentication_token`. [4](#0-3) 
2. Request `GET /api/:stack_B_repo_owner/:stack_B_repo_name/:stack_B_environment/cc.xml?token=<stack_A's token>`.
3. `authenticate_api_client` succeeds (token is valid), and `stack` resolves to Stack B via the unscoped `Stack.from_param!(params[:stack_id])` call, bypassing the `current_api_client.stack_id` restriction that `BaseController#stacks` would have enforced.
4. The response reveals Stack B's deploy status/history even though the token was only authorized for Stack A.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
