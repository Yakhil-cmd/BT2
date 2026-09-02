### Title
Stack-scoped API token can be used to read *any* stack's CI status via CCMenuController - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` resolver to bypass the stack-scope check that every other API endpoint relies on, allowing a token that is authorized ("authorises") for only one stack to read the CI status of any stack ("touches") by supplying an arbitrary `stack_id` parameter.

### Finding Description
`ApiClient` records can be scoped to a single stack via the `belongs_to :stack, optional: true` association [1](#0-0) . The generic API base controller enforces this scope by resolving the target stack through `stacks`, which restricts the queryable set to `current_api_client.stack_id` when it is present: [2](#0-1) 

Every controller that calls the shared `stack` helper (e.g. `Api::RollbacksController`, `Api::StacksController#show`) is therefore bound by the equality: `stack acted upon == stack the token's stack_id authorizes`.

`Api::CCMenuController`, however, defines its own private `stack` method that resolves directly from the global `Stack` model instead of the scoped `stacks` relation, and only requires the generic `read:stack` permission: [3](#0-2) 

Because `require_permission :read, :stack` only checks `ApiClient#check_permissions!`, which merely tests whether the string `"read:stack"` is present in `permissions` and never consults `stack_id` [4](#0-3) , a token that was issued/scoped to Stack A (i.e., `api_client.stack_id == A.id`) will pass the permission check for `show` and then have `stack` resolved to whatever `stack_id` the caller supplies in the URL, including Stack B, C, etc. This breaks the "stack a token authorises vs. stack it touches" binding described in the rules.

### Impact Explanation
Any holder of a `read:stack`-scoped, stack-restricted API token (a normal, low-privilege capability intentionally limited to one stack, e.g. created for a single project's CCMenu widget) can enumerate other stacks' `id`/`to_param` values and retrieve their CI/deploy status, last build label, last build time, activity, and web URL for stacks they were never granted access to. This is an authorization-scope bypass leading to unauthenticated (relative to the intended scope) read of stack state/deploy status across repositories, matching the High-severity category "escalation into authorization scoping / unauthenticated read of stack state or deploy output."

### Likelihood Explanation
Exploitation requires possession of any valid `ApiClient` token with `read:stack` permission that is scoped to a single stack (a routine, low-privilege token type this engine explicitly supports and creates, e.g. via `CCMenuUrlController`/admin-created scoped clients). No repository write access, GitHub credentials, or session is needed — only the existing token and knowledge/guessing of another stack's identifier — so likelihood is high once such a scoped token exists.

### Recommendation
Make `Api::CCMenuController#stack` resolve through the shared, scope-aware `stacks` relation (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the stack a token is permitted to read is always exactly the stack it actually touches.

### Proof of Concept
1. Create/obtain an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A only (mirrors the `here_come_the_walrus` fixture pattern) [5](#0-4) .
2. Authenticate this token against `GET /api/stacks/:stack_id/ccmenu.xml` where `:stack_id` is set to Stack B's param (a stack this token was never scoped to).
3. `authenticate_api_client` succeeds and `require_permission :read, :stack` passes because the client has `read:stack` in `permissions` [4](#0-3) .
4. `stack` resolves via `Stack.from_param!(params[:stack_id])` directly to Stack B, bypassing the `stacks` scoping used elsewhere [6](#0-5) , and the controller renders Stack B's CI status/build info in the response.

### Citations

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-31)
```ruby
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
