### Title
CCMenu API endpoint bypasses ApiClient stack-scoping, letting a stack-scoped token read any stack's status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` redefines the `stack` lookup helper to bypass the stack-scoping enforced by `Api::BaseController`, so an `ApiClient` token that is authorized (`stack_id`-scoped) for only one stack can read the CI/build status of any stack in the installation.

### Finding Description
`Api::BaseController` derives the accessible stack set from the authenticated `ApiClient`'s scope: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped, and `stack` is built on top of that scoped relation via `stacks.from_param!`. This is the binding the rest of the API relies on: **a stack a token authorizes == the stack an action touches**.

`Api::CCMenuController` overrides this helper and drops the scoping entirely: [2](#0-1) 

`stack` here calls `Stack.from_param!(params[:stack_id])` directly (unscoped `Stack` relation), instead of the inherited scoped `stacks.from_param!(params[:stack_id])`. The controller's only authorization gate is the class-level permission declaration: [3](#0-2) 

`require_permission :read, :stack` only checks that the string `"read:stack"` is present in `ApiClient#permissions`; it never checks that `params[:stack_id]` matches `current_api_client.stack_id`: [4](#0-3) 

So the equality the rest of the API preserves (`current_api_client.stack_id? → Stack.where(id: current_api_client.stack_id)`) is broken specifically in this controller: before the fix (conceptually), any stack-scoped token with `read:stack` is confined to its own stack; after reaching `CCMenuController#show`, that same token can address `Stack.from_param!` for an arbitrary `stack_id`, i.e. `token.authorized_stack ≠ stack_touched`.

### Impact Explanation
`CCMenuController#show` renders `deploys_and_rollbacks.last` details (build status, lock state, name, URLs) for the requested stack: [5](#0-4) 

A token deliberately scoped to a single (possibly low-sensitivity) stack — e.g. `here_come_the_walrus`, fixture-scoped to `stack: shipit` with only `read:stack` — can be used to enumerate and read the deploy/build/lock status of every other stack in the Shipit instance, which is unauthorized cross-stack read of stack state. This matches the in-scope High-impact category "unauthenticated/unauthorized read of stack state ... deploy output."

### Likelihood Explanation
Any holder of a minimally-scoped `ApiClient` token (the intended, lowest-privilege credential type in this system, analogous to the report's "valid staking position") can trivially perform this: no additional secrets, no elevated permission, and no interaction with GitHub credentials are required — only changing the `stack_id` route/query parameter on a request that is otherwise legitimate for their own stack.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it using the inherited scoped `stacks.from_param!`) so CCMenu lookups respect `ApiClient#stack_id` scoping identically to every other API controller.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A>.id` with permission `read:stack` (e.g., fixture `here_come_the_walrus`).
2. Authenticate as that client (Basic auth header or `?token=` query param, per `authenticate_api_client` override at [6](#0-5) ).
3. Request `GET /:other_stack_B_id.xml` (ccmenu show route) using `stack_id` of a different stack B that the client is not scoped to.
4. `stack` resolves via unscoped `Stack.from_param!`, `require_permission :read, :stack` passes (permission string present), and the response renders stack B's CCTray XML including build/lock status — despite the token being authorized only for stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
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
