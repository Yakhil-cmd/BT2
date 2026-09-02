## Finding [1](#0-0) 

### Title
Stack-scoped API tokens bypass their `stack_id` binding in the CCMenu endpoint, allowing cross-stack disclosure of deploy/task state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and every other API controller enforces that scope by resolving the requested resource through the `stacks` helper before looking it up by param. `Shipit::Api::CCMenuController` instead overrides `#stack` to look the stack up directly by `params[:stack_id]`, without ever consulting `current_api_client.stack_id`. This breaks the equality "stack a token authorizes == stack the request touches," letting a token that is only supposed to authorize one stack read the CI/deploy status of any stack in the installation.

### Finding Description
`ApiClient` supports scoping to a single stack: `belongs_to :stack, optional: true` [2](#0-1) . The generic `Api::BaseController` enforces this scope for every resource lookup:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [3](#0-2) 

Controllers like `Api::TasksController` and `Api::DeploysController` rely on this default `stack` method, so a scoped token can only ever resolve to its own stack [4](#0-3) [5](#0-4) . `Api::StacksController` overrides `#stack` but still routes through the scoped `stacks` helper: `@stack ||= stacks.from_param!(params[:id])` [6](#0-5) .

`Api::CCMenuController`, however, overrides `#stack` to bypass the scope entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [7](#0-6) 

The only authorization check remaining is `require_permission :read, :stack` [8](#0-7) , which only validates that `"read:stack"` is present in `current_api_client.permissions` — it never checks which specific stack the permission is scoped to [9](#0-8) . As a result, the binding "the stack this token authorizes" (`current_api_client.stack_id`) is never checked against "the stack this request touches" (`params[:stack_id]`) in this one controller, even though that check is the norm everywhere else in the API.

### Impact Explanation
Any holder of a legitimately-issued, single-stack-scoped `ApiClient` token with `read:stack` permission (e.g. a CCMenu client created for one project via `CCMenuUrlController#fetch` [10](#0-9) ) can substitute any other stack's `stack_id` in the request path and read that unrelated stack's deploy/task/CI status through `GET /api/:stack_id/ccmenu.xml`. This is an unauthorized cross-stack read of deploy state, escalating a token's granted scope beyond what it was issued for — directly analogous to the delegator/self-delegation bug class, where a state binding (delegate ⇄ delegator, here token ⇄ stack) is trusted implicitly instead of being re-validated at the point of use.

### Likelihood Explanation
Exploitation requires only possession of any valid, narrowly-scoped `ApiClient` token with `read:stack` permission — a routine, low-privilege credential that Shipit itself issues automatically (e.g., via the CCMenu URL feature). No elevated privileges, secrets, or additional access are needed beyond that single token, and the request is a simple parameter substitution.

### Recommendation
Make `Api::CCMenuController#stack` resolve through the same scoped `stacks` helper used by `Api::BaseController` and every other API controller, i.e. `@stack ||= stacks.from_param!(params[:stack_id])`, so that a stack-scoped token can never resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id: A` with `permissions: ["read:stack"]` (e.g. via `CCMenuUrlController#fetch` for stack A).
2. Using that token's `authentication_token`, call `GET /api/<owner>/<repo-B>/<env-B>/ccmenu.xml?token=<token>` where `repo-B/env-B` is a completely unrelated stack B.
3. `authenticate_api_client` succeeds (valid token) and `require_permission :read, :stack` passes (token has `read:stack`).
4. `stack` resolves via `Stack.from_param!(params[:stack_id])`, ignoring that the token's `stack_id` is A, and returns stack B's deploy/task status — a stack the token was never authorized to access.

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
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

**File:** app/controllers/shipit/api/tasks_controller.rb (L9-11)
```ruby
      def index
        render_resources(stack.tasks)
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L8-10)
```ruby
      def index
        render_resources(stack.deploys_and_rollbacks)
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
