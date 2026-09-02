### Title
Stack-scoped API tokens can read the build status of arbitrary stacks via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via the `stack_id` column, and `Shipit::Api::BaseController` enforces that scope by resolving the target stack through the `stacks` helper, which restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the token is stack-scoped. `Shipit::Api::CCMenuController` overrides the `stack` accessor to look up the target directly via `Stack.from_param!(params[:stack_id])`, bypassing that scoping entirely, so any valid CCMenu token can be used to read the CI/build status of any stack in the instance, not just the one it was issued for.

### Finding Description
`Shipit::Api::BaseController` defines the scoping binding between an `ApiClient` token and the stacks it is permitted to touch: [1](#0-0) 

`stacks` restricts the queryable stacks to the one identified by `current_api_client.stack_id` when the token is stack-scoped, and `stack` resolves `params[:stack_id]` only within that restricted relation. Every other API controller (e.g. `Shipit::Api::DeploysController`) inherits this `stack` method and is therefore correctly bound to the token's authorized stack.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass the scoped relation entirely: [2](#0-1) 

It only declares `require_permission :read, :stack`, which merely checks that the token's `permissions` array contains `"read:stack"` — it does not check whether the token's `stack_id` matches the requested `params[:stack_id]`: [3](#0-2) 

CCMenu tokens are explicitly designed to be single-stack-scoped and widely distributed (e.g. embedded in CI dashboard tool URLs), created via `Shipit::CCMenuUrlController`: [4](#0-3) 

This breaks the binding: `token.stack_id == requested_stack` before the change in trust vs. `token.stack_id != requested_stack` after — i.e. **the stack a token authorizes ≠ the stack it actually touches**. Any holder of a legitimately-issued, stack-A-scoped CCMenu token can simply change the `stack_id` request parameter to read stack B's (or any other stack's) build/deploy status, name, last build label/time, and web URL.

### Impact Explanation
This is a High-impact issue: it is an "unauthenticated" (from the perspective of the target stack) read of stack state that escalates beyond the authorization the token was actually granted — a holder of a narrowly-scoped, low-privilege token (`read:stack` limited to one stack) gains read access to every stack's build/deploy status in the Shipit instance, including stacks they have no legitimate access to. This is a direct instance of the "stack a token authorises versus a stack it touches" trust binding called out as in-scope.

### Likelihood Explanation
Any Shipit user who has ever been issued (or can obtain) a CCMenu token for a single stack — which is a normal, low-privilege, self-service action available via `Shipit::CCMenuUrlController` — can immediately exploit this by substituting a different `stack_id` in the request. No special privileges, secrets, or social engineering are required beyond having one legitimate scoped token, making this straightforward and reliably reproducible.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (or reimplement it to use the inherited, scope-respecting `stacks.from_param!(params[:stack_id])`) so that stack-scoped tokens cannot resolve stacks outside their authorized `stack_id`.

### Proof of Concept
1. As a legitimate low-privilege user, visit `CCMenuUrlController#fetch` for `stack_id: "org/repo-a/production"`. This creates/returns an `ApiClient` with `permissions: %w[read:stack]` scoped to `stack_id` = repo-a's stack, and returns an authentication token embedded in a CCMenu URL.
2. Send `GET /api/org/repo-b/production/cc.xml?token=<token-from-step-1>` (i.e., swap `stack_id` in the URL to a different, unauthorized stack "repo-b").
3. Observe that `Shipit::Api::CCMenuController#show` renders repo-b's `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` — even though the token was scoped only to repo-a — because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of the scope-checked `stacks.from_param!` used everywhere else in the API.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
