### Title
Stack-scoped API token bypasses `stack_id` scoping in the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`ApiClient` tokens can be scoped to a single stack via `stack_id`, and `Api::BaseController` is supposed to enforce that scoping for every API request. `Api::CCMenuController` overrides the `stack` lookup method and bypasses that scoping entirely, letting any authenticated token (even one restricted to a single stack) read the CI/deploy status of any stack in the installation.

### Finding Description
`Api::BaseController` defines the trust binding "the stack a token authorizes == the stack it can touch": [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Every other API controller inherits this scoped `stack` helper (e.g. `Api::StacksController`, `Api::CommitsController`), so a token created with `stack_id` set can only ever resolve records for that one stack.

`Api::CCMenuController`, however, redefines `stack` independently of the scoped `stacks` collection: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`require_permission :read, :stack` only checks that the token has the string permission `read:stack` via `ApiClient#check_permissions!`: [3](#0-2) 

It never checks that the resolved `stack` is the one the token is bound to. Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, the `current_api_client.stack_id` restriction from `BaseController#stacks` is never applied. Any token with `read:stack` permission — even one explicitly created with `stack_id` set to authorize only stack A — can pass an arbitrary `params[:stack_id]` and read the build/deploy status of stack B, C, etc.

This mirrors the reported bug class: an authorization/scope check exists (`stack_id` binding a token to one stack, analogous to the "amount staked"), but the actual resource acted upon (`stack` in `CCMenuController#show`) is resolved without applying that scope, effectively granting the token "voting power" (read access) over all stacks regardless of the amount (breadth) it was actually authorized for.

### Impact Explanation
This breaks the "stack a token authorises" vs "stack it touches" binding called out in scope. It allows unauthenticated-relative-to-other-stacks read of stack state (last build status, last build label, build time, web URL) for any stack in the Shipit installation using a token that was deliberately scoped to a single stack. This matches the High severity criterion: "escalation into ... unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Any holder of a legitimately-issued, narrowly-scoped `ApiClient` token (e.g. a CI integration meant to only see one stack's CCMenu status) can trivially exploit this by changing the `stack_id` URL parameter — no additional privileges, signatures, or secrets are required beyond the token they already legitimately possess.

### Recommendation
Make `Api::CCMenuController#stack` use the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction is enforced consistently with every other API controller.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A only: `ApiClient.create!(creator: user, name: "ci-a", stack_id: stack_a.id, permissions: ["read:stack"])`.
2. Using that client's `authentication_token`, request `GET /api/stacks/:stack_b_id/ccmenu.xml` with `token=<client token>` where `stack_b_id` belongs to Stack B, which the token was never authorized for.
3. Observe the request succeeds (HTTP 200) and returns Stack B's build status XML, even though `current_api_client.stack_id` is Stack A — confirming the scoping bypass, since the same request against `Api::StacksController#show` with the analogous scoped `stack` lookup would correctly 404/be excluded by `stacks.from_param!`.

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
