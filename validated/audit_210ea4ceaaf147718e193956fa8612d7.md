### Title
`Shipit::Api::CCMenuController#stack` bypasses `current_api_client.stack_id` scoping - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController#stack` resolves the target stack through `stacks`, which restricts lookups to `current_api_client.stack_id` when the token is stack-scoped. `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, skipping that scoping entirely, so a token issued for stack A can be used to read the CCMenu status of any other stack B.

### Finding Description
The intended binding is: for any API request authenticated with a stack-scoped `ApiClient`, `resolved_stack ∈ {stack : stack.id == current_api_client.stack_id}` — enforced by `BaseController#stacks`: [1](#0-0) 

`CCMenuController` overrides `stack` and never calls `stacks`: [2](#0-1) 

`#show` calls this overridden `stack`, and `require_permission :read, :stack` only checks whether the client's `permissions` array contains `"read:stack"` — it never checks `current_api_client.stack_id` against the requested stack: [3](#0-2) [4](#0-3) 

Attacker request: `GET /api/stacks/:owner/:repo/:branch/cc.xml?token=<tokenA>` (or via `token` param/basic auth) where `tokenA` authenticates an `ApiClient` created with `stack_id: A.id, permissions: ['read:stack']`, but `params[:stack_id]` (the route path segment identifying owner/repo/branch) refers to stack B. `authenticate_api_client` in `CCMenuController` successfully sets `@current_api_client` to client A: [5](#0-4) 

`require_permission!` passes because A has `read:stack`. `stack` then resolves stack B unconditionally via `Stack.from_param!`, and `#show` renders B's latest deploy/build status. Before/after the equality: before, `resolved_stack == A` was intended; after tracing, `resolved_stack == B`, and `B ∉ {A}` — the binding is broken. No other guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters`, model validators) is on this path since this is a GET read request with no webhook or payload involved.

### Impact Explanation
An attacker holding any legitimately-issued single-stack CCMenu/API token (these are routinely embedded in CCMenu URLs, CI dashboards, etc., and are not treated as highly secret) can read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state) of any other stack in the Shipit instance, including stacks belonging to different repositories/tenants, simply by changing the `stack_id` route segment. This is an unauthenticated-scope read of another tenant's stack state, repeatable for every stack in the instance, matching the "High: unauthenticated read of stack state" category.

### Likelihood Explanation
Preconditions are minimal and match normal Shipit usage: any existing `ApiClient` scoped to one stack (the common case for CCMenu integration) is sufficient; the attacker does not need `api_clients_secret`, GitHub credentials, or any elevated role — only a token that was already handed to them for their own stack. The only extra "cost" is guessing/knowing another stack's identifying path (owner/repo/branch), which is often public information (GitHub repo names are typically visible). This is trivially repeatable against every stack on the instance.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (or reimplement it to call `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!`) so that CCMenu lookups are scoped through `current_api_client.stack_id` exactly like the base controller.

### Proof of Concept
Minitest plan (in `test/controllers/api/ccmenu_controller_test.rb` context, not to be placed in excluded paths for the fix but demonstrating the bug):
1. Create `stackA = Stack.create!(repository: Repository.new(owner: "acme", name: "app-a"), branch: "main")`.
2. Create `stackB = Stack.create!(repository: Repository.new(owner: "other", name: "app-b"), branch: "main")`.
3. Create `clientA = ApiClient.create!(creator: user, name: "a", stack_id: stackA.id, permissions: ['read:stack'])`.
4. Assert binding before: `clientA.stack_id == stackA.id` and `stackA.id != stackB.id`.
5. `get :show, params: { stack_id: stackB.to_param, token: clientA.authentication_token }`.
6. Assert `response.status == 200` and the rendered XML `Project name` corresponds to `stackB.to_param`, not `stackA.to_param` — demonstrating `resolved_stack == stackB` even though `current_api_client.stack_id == stackA.id`, proving the scoping binding is broken. Expected secure behavior (post-fix): response should be `404 Not Found` (via `stacks.from_param!` raising `NotFound` since `stackB` is not in the `current_api_client`-scoped relation).

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-25)
```ruby
    class CCMenuController < BaseController
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
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
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
