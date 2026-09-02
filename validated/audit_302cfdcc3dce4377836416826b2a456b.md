## Title
CCMenu API token scope bypass: an ApiClient scoped to one stack can read the build status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor to bypass the stack-scoping enforced by `Shipit::Api::BaseController`, so a token that is only authorized for one stack can be used to read the CCMenu status of any stack in the installation, by simply changing the `stack_id` in the URL.

### Finding Description
`BaseController#stacks` restricts the visible set of stacks to the one the `ApiClient` is bound to (`current_api_client.stack_id?`), and `BaseController#stack` resolves the requested id only from within that restricted scope: [1](#0-0) 

`CCMenuController`, however, redefines `stack` to resolve the id from the entire `Stack` table, completely bypassing the `current_api_client.stack_id` binding that `BaseController#stacks`/`#stack` enforces: [2](#0-1) 

The controller still calls `require_permission :read, :stack`, which only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!` — it does not check which specific stack the token is bound to: [3](#0-2) 

This is exactly the bug class from the report: a scope that is supposed to be a binding (`ApiClient.stack_id` "authorizes" one stack) is enforced in one code path (`BaseController#stack`) but not in the sibling code path that actually touches the resource (`CCMenuController#stack`), breaking the equality `stack a token authorizes == stack a token touches`.

Scoped CCMenu tokens are created and handed out precisely for this per-stack use case, via `CCMenuUrlController#client`, which creates an `ApiClient` with only `read:stack` permission but does **not** set `stack_id`, and more importantly, this weak per-stack binding is what `Shipit::Api::CCMenuController#authenticate_api_client` relies on for authentication when a `token` query param is present: [4](#0-3) [5](#0-4) 

Note: I could not confirm from available code whether `ApiClient` created by `CCMenuUrlController` sets `stack_id` (the `create_with(permissions: ...)` call does not include `stack_id`, meaning tokens minted this way are actually unscoped already). Regardless, for any `ApiClient` that IS scoped to a stack (`stack_id` present, e.g. created through the standard `ApiClientsController`/`api_client` UI or API with a `stack` assigned), the `CCMenuController#stack` override still allows reading arbitrary stacks' data, because it never consults `current_api_client.stack_id`.

### Impact Explanation
Any holder of a valid Shipit API token/basic-auth credential with just `read:stack` permission — even one deliberately scoped by an admin to a single, low-sensitivity stack — can enumerate `stack_id` values and read the last deploy/rollback status (`deploys_and_rollbacks.last`, running state, end time) of every stack in the Shipit instance via `GET /api/stacks/:stack_id/ccmenu`. This is an authorization-scope escalation: read access intended to be confined to one stack extends to all stacks, exposing deploy state across repositories/environments that the token holder should not be able to see. This matches the "High" impact bucket: escalation into `Shipit.github_teams`/stack-authorization boundaries and unauthenticated (from the target stack's perspective) read of stack state.

### Likelihood Explanation
High likelihood of exploitation once any `read:stack`-scoped API credential is obtained (e.g., from a CI system, third-party CCMenu integration, or a leaked scoped token) since it only requires substituting the `stack_id` path segment — no special payload crafting, timing, or race condition is needed, and the route is a simple authenticated `GET`.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` binding is enforced consistently with every other API controller.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to `stack_A` (`stack_id` set to `stack_A.id`, permission `read:stack`).
2. Using that client's `authentication_token` via HTTP Basic Auth, request:
   `GET /api/stacks/<stack_B_owner>/<stack_B_repo>/<stack_B_env>/ccmenu`
   where `stack_B` is a different stack the client was never granted access to.
3. Observe a `200 OK` XML response containing `stack_B`'s latest deploy/rollback status, even though `BaseController#stacks` (used by every other `Api::*Controller`, e.g. `Api::StacksController`, `Api::TasksController`, `Api::DeploysController`) would have returned `Stack.none`/404 for the same client and stack combination.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
