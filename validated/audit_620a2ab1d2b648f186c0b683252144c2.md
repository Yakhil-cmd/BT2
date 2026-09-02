### Title
Stack-scoped API token can read the deploy status of any stack via `CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper inherited from `BaseController` in a way that drops the scoping enforced for every other API resource, letting a token that is authorised only for one stack read the build/deploy status of *any* stack in the installation.

### Finding Description
`Shipit::Api::BaseController` binds every API request's target stack to the authenticated `ApiClient`'s scope: [1](#0-0) 
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This is the binding that should hold: `stack the token authorises == stack the request touches`. Every other API controller (`StacksController`, `TasksController`, etc.) relies on this same `stack`/`stacks` helper.

`CCMenuController`, however, re-defines `stack` to bypass the scoping entirely: [2](#0-1) 
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
It only declares `require_permission :read, :stack` at the class level: [3](#0-2) 

`ApiClient#check_permissions!` only checks that the client's `permissions` array contains `read:stack` — it never checks `stack_id`: [4](#0-3) 
```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
```
So the equality that must hold, `token.stack_id == params[:stack_id]` (when the token is stack-scoped), is enforced in `BaseController#stack` but silently broken in `CCMenuController#stack`, which resolves `Stack.from_param!(params[:stack_id])` against the *entire* `Stack` table regardless of `current_api_client.stack_id`.

### Impact Explanation
An `ApiClient` created for a single stack (e.g. via `CCMenuUrlController#client`, which explicitly creates a token scoped with `permissions: %w[read:stack]` and tied implicitly to the requesting stack context) can be replayed against `GET /api/:stack_id/cc.xml` for a different `stack_id`. Because `CCMenuController#stack` performs an unscoped lookup, the request succeeds and returns that other stack's `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, i.e. deploy state that the token was never authorised to read. This matches the "High" impact category: unauthenticated (out-of-scope) read of stack state/deploy output using a token whose authorisation was supposed to be confined to one stack.

### Likelihood Explanation
Any holder of a legitimately-scoped, low-privilege `read:stack` CCMenu token (these tokens are routinely shared with third-party CI dashboards, since `CCMenuUrlController` embeds the token directly in a URL) can trivially exploit this by changing the `stack_id` segment of the URL — no additional credentials, signature, or session are required, only the one CCMenu token they already legitimately hold.

### Recommendation
Make `CCMenuController#stack` reuse the scoped `stacks` helper from `BaseController` instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the binding `current_api_client.stack_id == stack acted upon` for the CCMenu endpoint, consistent with every other API controller.

### Proof of Concept
1. Operator visits a stack's CCMenu URL (`GET /:stack_id/ccmenu_url`), which creates/returns an `ApiClient` scoped to `stack_id: A` with `permissions: ['read:stack']` and its `authentication_token`. [5](#0-4) 
2. Attacker who obtains that token (e.g. from a shared CI dashboard config) issues:
   `GET /api/<STACK_B_ID>/cc.xml?token=<token_scoped_to_stack_A>`
3. `authenticate_api_client` in `CCMenuController` accepts the token via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because the token has `read:stack` permission (it doesn't check which stack).
4. `stack` resolves `Stack.from_param!(params[:stack_id])` = Stack B, unrelated to the token's `stack_id` = A.
5. Response renders Stack B's deploy/build status (`shipit/ccmenu/project` view), which the token was never authorised to access.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
