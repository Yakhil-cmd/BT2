### Title
Api::CCMenuController bypasses the api_client-to-stack authorization scope, breaking the binding "stack a token authorises == stack it touches" - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` looks up the target `Stack` directly from the URL parameter instead of through the scoped `stacks` collection that every other API controller uses, so an `ApiClient` token that is restricted to a single stack can read the build/deploy status of any other stack in the installation.

### Finding Description
`Api::BaseController` is designed so that any authenticated `ApiClient` can only operate on the stack(s) it is authorized for: [1](#0-0) 
```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This is the binding: `current_api_client.stack_id (the stack the token authorises)` == `params[:stack_id] resolved only within that scope`. This binding is enforced and tested for the generic `Api::StacksController` ("an api client scoped to a stack will only see that one stack").

`Api::CCMenuController`, however, overrides `stack` and bypasses the scoped `stacks` collection entirely: [2](#0-1) 
```
private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```
It still calls `require_permission :read, :stack`, which only checks the *type* of permission the token has (`read:stack` present in `permissions`), not whether the token is scoped to the specific stack being requested: [3](#0-2) 
```
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
  end
  true
end
```
Because `stack` resolves `params[:stack_id]` against `Stack.from_param!` (all stacks) rather than `stacks.from_param!` (the client's authorized scope), the equality `current_api_client.stack_id == requested_stack.id` that the rest of the API enforces is never checked here. Any valid, unrevoked `ApiClient` token that only carries `read:stack` and is scoped to stack A can be replayed against `GET /api/:stack_id/ccmenu` for any other stack B, and the request succeeds.

This is the direct analog of the `EloCalculator` bug pattern: a verification/authorization step is applied using the wrong operand (the un-scoped `Stack` collection instead of the token-scoped `stacks` collection), so the "authorised" entity and the "acted-upon" entity diverge.

### Impact Explanation
The `ccmenu#show` action renders the stack's CI/deploy status (last deploy id, state, timestamps): [4](#0-3) 
```
def show
  latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
  render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
end
```
An attacker holding any legitimate, narrowly-scoped `read:stack` token (e.g. handed out for one stack via `CCMenuUrlController#client`, or created by an admin scoped to a single stack) can enumerate/query deploy state for arbitrary stacks across the whole Shipit instance, including private/other teams' repositories, without ever holding a token authorized for those stacks. This matches the "High - unauthenticated read of stack state, task streams or deploy output" impact category, since it discloses task/deploy state outside the token's granted scope.

### Likelihood Explanation
Likelihood is high for anyone who already possesses a single-stack-scoped API token (a routine, low-privilege credential distributed for CI dashboard integration via `CCMenuUrlController`). No additional privilege, session, or GitHub access is required — only a valid `ApiClient` token with `read:stack` permission, which is the exact class of credential this feature is designed to hand out broadly (CCMenu urls are typically embedded in CI dashboard tools). The only variable is that the attacker must already hold *some* `read:stack` token; the vulnerability is that this token is not confined to its intended stack when used against this specific endpoint.

### Recommendation
Make `Api::CCMenuController#stack` honor the same scoping as the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
where `stacks` is inherited from `Api::BaseController` (respecting `current_api_client.stack_id`), instead of calling `Stack.from_param!` directly.

### Proof of Concept
1. As a legitimate admin, create (or let `CCMenuUrlController` auto-create) an `ApiClient` scoped to Stack A only, with permission `read:stack`, and obtain its `authentication_token` (e.g. via `GET /ccmenu/*stack_A_id`, which returns a `ccmenu_url` containing `?token=<token>`).
2. As the holder of that token (no other credentials), issue:
   ```
   GET /api/<stack_B_owner>/<stack_B_repo>/<stack_B_env>/ccmenu?token=<token>
   ```
   for any other stack B in the installation.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the client-scoped `stacks.from_param!`, the request succeeds with HTTP 200 and returns stack B's deploy/CI status XML, even though the token was only ever authorized for stack A. Compare with `Api::StacksController#show` using the same token against `/api/stacks/<stack_B_id>`, which correctly returns nothing/403 because it uses the scoped `stacks` collection — demonstrating the divergence introduced by `CCMenuController`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-26)
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
