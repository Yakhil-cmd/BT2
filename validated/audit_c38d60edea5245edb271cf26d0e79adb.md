### Title
Scoped ApiClient tokens can read the status of any stack via `Api::CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` enforces per-stack token scoping by resolving `stack` through a `stacks` relation that is filtered to `current_api_client.stack_id` when the token is stack-scoped. `Api::CCMenuController` overrides this `stack` lookup with an unscoped `Stack.from_param!(params[:stack_id])`, breaking the binding between "the stack a token is authorized for" and "the stack the request actually touches."

### Finding Description
`Api::BaseController#stack` restricts lookups to the token's authorized stack: [1](#0-0) 

This is the mechanism that turns the generic permission string `read:stack` (checked only as a string, with no stack identity) into an actual per-stack authorization boundary — `check_permissions!` merely checks that `"read:stack"` is in the token's `permissions` array, with no reference to which stack: [2](#0-1) 

`Api::CCMenuController`, however, defines its own private `stack` method that bypasses the scoped `stacks` relation entirely and looks up **any** stack in the instance by param: [3](#0-2) 

Because `require_permission :read, :stack` only validates the string permission (not stack identity), and the controller's own `stack` override never applies `current_api_client.stack_id` filtering, a token that was created scoped to Stack A (e.g. the `here_come_the_walrus` fixture, which has `stack: shipit` and only `read:stack` permission) can be replayed against `GET /api/stacks/*stack_id/ccmenu` with any other `stack_id` in the same Shipit installation and will succeed, returning that other stack's CI/deploy status.

This is structurally the same class of bug as the reported `gracePeriod` issue: a value that is supposed to be updated/enforced together with another value (`membership.creation` / `gracePeriod`, here `permission scope` / `stack identity`) is only partially applied, so the intended invariant ("`read:stack` permission is valid only for the stack the token is bound to") silently does not hold in this one code path even though it holds everywhere else (`StacksController`, `TasksController`, `DeploysController`, etc., which all use the inherited scoped `stack`/`stacks` methods from `BaseController`).

### Impact Explanation
This breaks the binding: `stack a token authorizes == stack a token can touch`. An attacker holding a legitimately-issued, stack-scoped API token (e.g. obtained via the CCMenu URL feature, which itself mints such scoped tokens: `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)` in `CCMenuUrlController`) can use it to read stack state (deploy status, last build status, activity) for stacks it was never granted access to. This matches the "High — unauthenticated/unauthorized read of stack state" impact category, since it is a cross-stack authorization bypass for a token that was deliberately scoped to a single stack.

### Likelihood Explanation
Likelihood is high for anyone who already holds a stack-scoped `ApiClient` token (a normal, low-privilege credential intentionally restricted to one stack, e.g. via the CCMenu integration). No special access beyond having one such token is required — the attacker only needs to change the `stack_id` in the URL. The only precondition (having *a* valid stack-scoped token) is explicitly not out of scope per the rules, since it is a normal artifact users are meant to receive (e.g. via `CCMenuUrlController#fetch`) with intentionally reduced permissions.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped `stacks` relation from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!(params[:stack_id])`, so stack-scoped tokens cannot be used to read data belonging to a different stack.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id` = Stack A, with permission `read:stack` only (this is exactly what `CCMenuUrlController#fetch` does automatically for any logged-in user, per `app/controllers/shipit/ccmenu_url_controller.rb:15-18`).
2. Using that token's `authentication_token` for Basic Auth, request `GET /api/stacks/<Stack B owner>/<Stack B repo>/<Stack B env>/ccmenu` for an unrelated Stack B that the token was never scoped to.
3. Observe that `Api::CCMenuController#stack` resolves Stack B via `Stack.from_param!(params[:stack_id])` (bypassing the `current_api_client.stack_id` filter used elsewhere), and the response renders Stack B's CI/build status (HTTP 200) instead of a 404/403 that would occur if the inherited scoped `stack`/`stacks` method from `BaseController` were used, as in `StacksController#show` or other scoped API endpoints.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
