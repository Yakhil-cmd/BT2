### Title
Stack-scoped `ApiClient` token can read CI/build status of any stack via the CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` restricts stack lookups to the stack an `ApiClient` token is scoped to, but `Shipit::Api::CCMenuController` overrides the `stack` accessor to bypass that scoping, breaking the binding **"stack a token authorises == stack it touches."**

### Finding Description
`ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . The base API controller enforces this scoping for every stack lookup:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Any controller inheriting `BaseController#stack` therefore can only resolve a stack that the authenticated `current_api_client` is actually scoped to (or any stack, if the token is unscoped).

`CCMenuController`, however, redefines `stack` to hit the model directly, skipping the `stacks` scope entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`Stack.from_param!` is a bare class-level lookup with no client/permission filtering: it just resolves whatever `owner/name/environment` is given in the URL [4](#0-3) .

Permission enforcement in the controller (`require_permission :read, :stack`) only checks that the token carries the `"read:stack"` permission string — it never verifies that the *specific* stack being accessed matches the token's `stack_id`:

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [5](#0-4) 

So the *only* place the stack_id-vs-token binding is actually enforced is inside `BaseController#stacks`, and `CCMenuController` is the one controller in the API namespace that does not go through it.

### Impact Explanation
An `ApiClient` token that was deliberately scoped to Stack A (e.g. via console/admin assignment of `stack_id`, a supported and tested feature — see `test "an api client scoped to a stack will only see that one stack"` in `test/controllers/api/stacks_controller_test.rb`) can be replayed against `GET /api/*stack_id/ccmenu` with an arbitrary other stack's identifier (Stack B) and successfully retrieve Stack B's build/deploy status (name, last build status/label/time, lock state) — data the token holder was never authorized to read. This is an unauthenticated-for-that-resource read of stack state across the token's authorization boundary, matching the High-impact category "unauthenticated read of stack state."

### Likelihood Explanation
Any holder of a valid, deliberately stack-restricted `ApiClient` credential (e.g. a CI integration or partner given narrow, single-stack read access) can trigger this simply by changing the `stack_id` path segment of the CCMenu URL — no additional privilege, signature bypass, or special access is required beyond possessing that one legitimately-scoped token.

### Recommendation
Remove the `stack` override in `CCMenuController` (or reimplement it using the inherited `stacks.from_param!(params[:stack_id])`) so CI-menu lookups are subject to the same `current_api_client.stack_id` scoping enforced everywhere else in `Shipit::Api::BaseController`.

### Proof of Concept
1. Create/obtain an `ApiClient` with `permissions: ["read:stack"]` and `stack_id` set to Stack A's id (a supported configuration, exercised in `test/controllers/api/stacks_controller_test.rb`, e.g. fixture `here_come_the_walrus`).
2. Authenticate with this token via Basic Auth against `GET /api/<stack_B_owner>/<stack_B_name>/<stack_B_env>/ccmenu`.
3. `CCMenuController#authenticate_api_client` succeeds (valid token), `require_permission :read, :stack` passes (`check_permissions!` only checks the permission string, not the stack id), and `CCMenuController#stack` resolves Stack B directly via `Stack.from_param!`, bypassing the `stacks` scope that would normally restrict lookups to Stack A only.
4. The response renders Stack B's CI/build status XML, even though the token was scoped exclusively to Stack A.

### Citations

**File:** app/models/shipit/api_client.rb (L4-9)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```
