## Analysis

The report's bug class — a resource-authorization check that is bypassed because a control-plane invariant (per-account offset) is skipped on a particular code path — maps onto Shipit's API authorization model as **a stack a token authorises versus a stack it touches**.

`Shipit::Api::BaseController` enforces per-token stack scoping via its `stacks`/`stack` helpers: [1](#0-0) 

`current_api_client.stack_id?` restricts a scoped `ApiClient` (created e.g. via `ApiClientsController`, `belongs_to :stack`) to only the one stack it was issued for; `stack` then resolves `params[:stack_id]` only from that restricted relation. This is the sole mechanism that binds a scoped token's authorized stack to the stack actually acted upon — `ApiClient#check_permissions!` only checks the permission string (`read:stack`), never the stack identity: [2](#0-1) 

`Shipit::Api::CCMenuController`, however, overrides `stack` and completely bypasses this scoping: [3](#0-2) 

`stack` here is defined as `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table, not through `stacks` (the scoped relation). `require_permission :read, :stack` still only checks the permission string, not stack identity, so any valid `read:stack` scoped token — no matter which single stack it was created for — can be replayed against `/api/stacks/<any-other-org>/<any-other-repo>/<any-env>/ccmenu?token=...` to read that other stack's deploy/build status.

### Title
Stack-scoped API token authorization bypass via `CCMenuController#stack` — unauthorized cross-stack read of deploy state ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution method used everywhere else in the API to enforce per-token stack scoping, replacing it with an unscoped `Stack.from_param!(params[:stack_id])` lookup. As a result, an `ApiClient` token that was deliberately scoped to a single stack (`belongs_to :stack`) with only `read:stack` permission can be used to read the CCMenu deploy-status feed of any other stack in the Shipit instance.

### Finding Description
The engine's stack-scoping invariant is: `ApiClient#stack_id` (if present) authorizes the token for exactly that stack; `Shipit::Api::BaseController#stacks`/`#stack` is the only place enforcing "the stack a token authorises" == "the stack a request touches": [1](#0-0) 

Permission checking is orthogonal and stack-agnostic: [2](#0-1) 

`CCMenuController` redefines `stack` (private method, same name, overriding the inherited one) to bypass the scoped `stacks` relation entirely: [3](#0-2) 

Because `show` calls this overridden `stack` method, and `require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)` (a flat string check), the equality "stack authorised by token" == "stack acted upon" is broken specifically on this controller, even though it holds everywhere else in the API (`Api::TasksController`, `Api::StacksController`, etc., which rely on the inherited `stack`/`stacks`).

### Impact Explanation
An attacker holding any legitimately issued `read:stack`-scoped `ApiClient` token — including one explicitly scoped to a single stack via the `belongs_to :stack` association — can enumerate and read the deploy/build status (`id`, `running?`, `ended_at`, embedded in the CCMenu XML) of every stack across every repository and organization managed by the Shipit instance, not just the one it was authorized for. This is an unauthenticated-relative-to-other-stacks read of deploy state, matching the High-severity criterion "unauthenticated read of stack state ... or deploy output" in spirit, since the token was never authorized for the target stack.

### Likelihood Explanation
Any holder of a stack-scoped, `read:stack`-permissioned `ApiClient` token (a routine, low-privilege credential handed to CI dashboards/plugins via the CCMenu feature) can trivially exploit this by substituting a different `stack_id` in the URL. No special privileges, GitHub App key, or webhook secret are required beyond possessing one valid, narrowly-scoped token.

### Recommendation
Remove the `stack` override in `CCMenuController`, or reimplement it to go through the inherited `stacks` relation (`stacks.from_param!(params[:stack_id])`) so token-to-stack scoping is enforced consistently with the rest of the API.

### Proof of Concept
1. An administrator creates (or the CCMenu-URL feature auto-creates) an `ApiClient` scoped to `stack: shipit-org/app-a/production` with `permissions: ['read:stack']`, via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` [4](#0-3) , producing `authentication_token` for that stack only.
2. The token holder issues:
   `GET /api/stacks/other-org/other-repo/production/ccmenu?token=<the-token>`
3. `CCMenuController#authenticate_api_client` accepts the token (it's a valid `ApiClient`); `require_permission :read, :stack` passes because the token has `read:stack` in its permission list, regardless of which stack.
4. `stack` resolves via `Stack.from_param!(params[:stack_id])` directly, returning `other-org/other-repo/production` — a stack the token was never scoped to — and its deploy status is rendered.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
