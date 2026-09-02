### Title
CCMenu API controller bypasses ApiClient stack-scoping, letting a stack-scoped token read the CCMenu status of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces an equality binding between the stack(s) an `ApiClient` token is *authorized* for and the stack(s) a request may *touch*: `stacks` restricts the visible `Stack` set to `current_api_client.stack_id` when the token is scoped, and every other API controller resolves its target stack through that scoped relation via `stacks.from_param!`. `Shipit::Api::CCMenuController` breaks this binding by overriding `stack` to resolve directly against the global `Stack` model instead of the scoped `stacks` relation, so a token that is only supposed to authorize one stack can be replayed against the `stack_id` of any other stack.

### Finding Description
The intended binding is enforced in `Shipit::Api::BaseController`: [1](#0-0) 

`stacks` filters to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is stack-scoped, and `stack` resolves the requested `params[:stack_id]` only within that scoped relation. Every "normal" API controller (`CommitsController`, `TasksController`, `DeploysController`, `RollbacksController`, `HooksController`, `StacksController`) relies on this inherited `stack`/`stacks` method, so a token whose `stack_id` is set can never touch a different stack, even though it has been granted the `read:stack`/`write:stack`/`deploy:stack` permission bit.

`Shipit::Api::CCMenuController` overrides both `authenticate_api_client` (to accept a plain `?token=` query param instead of Basic Auth) and `stack`: [2](#0-1) 

`stack` calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model class — the same pattern used by the model's own class method, not the token-scoped `stacks` relation from `BaseController`. `require_permission :read, :stack` (line 6) only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!`: [3](#0-2) 

`check_permissions!` never inspects `stack_id`; it only checks the permission name is in the token's `permissions` array. As a result, any `read:stack` token — including one that is `stack_id`-scoped to a single stack — passes `require_permission :read, :stack` regardless of which `stack_id` is requested, and `CCMenuController#stack` will happily look up and render the CCMenu status for that arbitrary stack.

This is the exact class of bug in the external report: `BalancerRouter` hardcodes/misresolves the token it checks balances against instead of using the pool-specific token, causing operations to act on the wrong entity than the one the caller is entitled to. Here, `CCMenuController` "hardcodes" the lookup path to the global, unscoped `Stack` table instead of using the ApiClient's authorized (scoped) stack set — the binding `stack authorized-by-token == stack touched-by-controller` is broken.

### Impact Explanation
An `ApiClient` token that was issued (e.g., via `Shipit::CCMenuUrlController#client` or manually through the `api_clients_controller`) with a `stack_id` restricting it to one specific stack can be used to read the CCMenu deploy-status XML (`latest_deploy`, running state, deploy id/timestamp) of **every other stack** in the Shipit instance by simply changing `stack_id` in the URL. This is an unauthorized cross-stack read of stack/deploy state using a credential that was never authorized for that stack, matching the High-severity class "unauthenticated read of stack state ... or deploy output" via escalation past the token's intended authorization scope.

### Likelihood Explanation
Any holder of a valid, narrowly-scoped `read:stack` `ApiClient` token (e.g., a CCMenu URL shared with a CI dashboard, or a per-team token) can trivially exploit this by changing the `stack_id` path/query parameter — no additional privileges, GitHub session, or write access are required, only possession of one legitimately-scoped token.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and use the inherited, token-scoped `stacks.from_param!` from `BaseController` instead of `Stack.from_param!`, so the resolved stack is always constrained to `current_api_client`'s authorized `stack_id` (or `Stack.all` only for unscoped clients), consistent with every other API controller.

### Proof of Concept
1. Obtain a CCMenu token scoped to `stack_id = A` (e.g., via `GET /A/ccmenu_url`, which mints an `ApiClient` with `read:stack` permission).
2. Call `GET /api/A/ccmenu.xml?token=<token>` — succeeds as intended.
3. Call `GET /api/B/ccmenu.xml?token=<token>` where `B` is an unrelated stack the token was never authorized for.
4. `CCMenuController#stack` resolves `B` via `Stack.from_param!(params[:stack_id])` (bypassing the `current_api_client.stack_id` restriction enforced everywhere else), `require_permission :read, :stack` passes because the token has the `read:stack` string, and the response discloses stack `B`'s deploy status — a cross-stack authorization bypass using a token scoped to a different stack.

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
