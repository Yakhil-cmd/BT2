### Title
CCMenu API token scoped to one stack can read CI/build state of any other stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` implements a per-token stack-scoping mechanism: an `ApiClient` may be bound to a single `stack_id`, and the `stacks` helper restricts queries to that stack when the token is scoped. [1](#0-0) . `Api::CCMenuController`, however, overrides the `stack` accessor to bypass this scoping helper entirely and load the stack directly from the class method `Stack.from_param!(params[:stack_id])`, ignoring the authenticated client's `stack_id` restriction. [2](#0-1) 

### Finding Description
The permission check `require_permission :read, :stack` only validates that the token's `permissions` array contains the string `"read:stack"`; it never validates which specific stack the token is entitled to. [3](#0-2) . The actual per-stack restriction is enforced only by routing lookups through `stacks` (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) before calling `.from_param!`. [1](#0-0) 

`CCMenuController#stack` does not call `stacks.from_param!`; it calls the unscoped `Stack.from_param!(params[:stack_id])` directly. [4](#0-3) . This breaks the binding: *the stack a token authorizes* (its bound `stack_id`) *versus the stack it actually touches* (whatever `stack_id` is supplied in the request path). Any client that legitimately created a "CCMenu Client" token scoped to Stack A — via `CCMenuUrlController`, which also builds its client with only `permissions: %w[read:stack]` and no explicit stack binding shown to be honored downstream — or any other token that merely carries `read:stack` in its permission list, can be replayed against `/api/stacks/:stack_id/ccmenu.xml` for an arbitrary `stack_id` belonging to Stack B, and the controller will happily render Stack B's build/deploy status.

Every other API controller (`StacksController`, etc.) resolves the current stack via the scoped `stacks` helper defined in `BaseController`, so this is a deviation specific to `CCMenuController`.

### Impact Explanation
This allows a holder of a narrowly-scoped, low-privilege token (created for CI status polling of one specific stack) to read the CI/build/deploy status of any stack in the Shipit instance, not just the one it was authorized for. This matches the specified High-impact category of "unauthenticated read of stack state, task streams or deploy output" achieved through a scope-authorization bypass (token authorized for stack A, but actually touches stack B).

### Likelihood Explanation
Any party that legitimately obtains one CCMenu token (e.g., a developer who fetches their own stack's CCMenu URL, or any client granted a `read:stack`-only ApiClient) can trivially exploit this by changing the `stack_id` path parameter in the CCMenu API request — no privileged access, GitHub credentials, or session is required beyond possessing one valid low-privilege token.

### Recommendation
Change `Api::CCMenuController#stack` (and `Shipit::CCMenuUrlController#stack`) to resolve the stack through the scoped `stacks` collection (`stacks.from_param!(params[:stack_id])`) instead of the bare `Stack.from_param!`, so that a token bound to a specific `stack_id` cannot be used to view any other stack's CCMenu data.

### Proof of Concept
1. User creates a CCMenu URL for Stack A via `GET /stacks/:stack_a_id/ccmenu_url`, which creates (or reuses) an `ApiClient` with `permissions: ["read:stack"]` and receives a token `T`. [5](#0-4) 
2. Attacker (or the same low-trust integrator) takes token `T` and issues `GET /api/stacks/:stack_b_id/ccmenu.xml?token=T` for an unrelated Stack B.
3. `authenticate_api_client` succeeds because `T` is a valid token. [6](#0-5) 
4. `require_permission :read, :stack` passes because the token has `read:stack` in its permissions, with no per-stack check. [3](#0-2) 
5. `stack` resolves via `Stack.from_param!(params[:stack_id])`, loading Stack B directly regardless of the token's intended scope, and Stack B's deploy/CI status is rendered to the caller. [7](#0-6)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
