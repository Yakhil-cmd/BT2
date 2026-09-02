### Title
Api::CCMenuController bypasses the ApiClient's stack scope, letting any valid `read:stack` token view CI/deploy status of stacks it was never authorized for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` scopes stack access to the `ApiClient`'s `stack_id` via the `stacks`/`stack` helpers [1](#0-0) , but `Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, skipping the `stacks` scoping entirely [2](#0-1) . This breaks the intended equality "stack a token authorizes == stack it touches": a token minted for (or restricted to) one stack can read the CI/build status of any other stack in the installation.

### Finding Description
`ApiClient` permissions are enforced at two levels: the permission string (`read:stack`, etc.) via `check_permissions!` [3](#0-2) , and the stack scope, applied by the base controller's `stacks` method which restricts the queryable `Stack` relation to `current_api_client.stack_id` when the client is stack-scoped [1](#0-0) . Every other API resource controller under `Shipit::Api` (deploys, tasks, rollbacks, commits, hooks scoping, etc.) resolves `stack` through this scoped `stacks` relation, so a client whose `stack_id` is set can only ever resolve to that one stack.

`Api::CCMenuController`, however, redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly against the entire `Stack` table, bypassing `stacks` and thus the `stack_id` restriction [2](#0-1) . The `require_permission :read, :stack` before-action only checks that the client possesses the `read:stack` permission string, not that it is scoped to the requested `stack_id` [4](#0-3) , [5](#0-4) .

Compounding this, the primary way CCMenu tokens are minted, `CCMenuUrlController#client`, creates an `ApiClient` with `permissions: %w[read:stack]` and no `stack_id` at all [6](#0-5) , meaning even the "happy path" produces a token that is unscoped by design and works for every stack in the Shipit instance, not just the one for which the CCMenu URL was requested. Even where an operator deliberately creates a stack-scoped `ApiClient` (e.g. fixture `here_come_the_walrus`, which is scoped to a specific stack and used elsewhere to verify per-stack isolation, e.g. `test/controllers/api/stacks_controller_test.rb`), that scoping is silently ignored by this specific controller because of the `Stack.from_param!` override.

This matches the report's bug class: a party (here, the token/`ApiClient`) is granted authority over a specific resource (its bound `stack_id`), but the controller's actual code path acts on an arbitrary resource (`params[:stack_id]`) that was never checked against that authorization — an equality (`token.stack_id == stack acted upon`) that the folio report's `Role::Owner` binding also violated by letting an authorized-for-code-changes actor act on baskets/tokens outside what was verified.

### Impact Explanation
Exploiting this only yields read access to `stack.deploys_and_rollbacks.last` status data (build/deploy state, label, timestamp, web URL) rendered as CCMenu XML [7](#0-6) . This is an "unauthenticated"-adjacent, unauthorized cross-stack read of stack state — matching the rules' High-severity bucket ("unauthenticated read of stack state, task streams or deploy output") to the extent that any valid CCMenu token (which is trivial to obtain for any stack one does legitimately have access to, since `CCMenuUrlController` mints one unscoped per user) can be replayed against every other stack's `stack_id` to read its status, without that token ever having been intended to authorize cross-stack reads. It does not permit writes, deploys, or credential exfiltration, so it stays within an information-disclosure impact rather than RCE/auth-bypass/credential-exfiltration territory.

### Likelihood Explanation
High: any user who has ever generated a CCMenu URL for a stack they can access possesses a token usable against arbitrary `stack_id` values, since `CCMenuUrlController` creates the underlying `ApiClient` without a `stack_id` restriction and `Api::CCMenuController` doesn't check one during rendering. No special privilege beyond having used the CCMenu feature once is required, and stack IDs (`owner/repo/environment`) are typically guessable/enumerable.

### Recommendation
- **Short term:** In `Api::CCMenuController`, resolve `stack` through the scoped `stacks` relation (as `BaseController#stack` does) instead of `Stack.from_param!` directly, so the `ApiClient#stack_id` restriction is honored.
- **Short term:** In `CCMenuUrlController#client`, create the `ApiClient` scoped to the specific `stack` (`stack:` attribute) rather than leaving it global, so each CCMenu token is inherently limited to the stack it was generated for.
- **Long term:** Add a shared/enforced concern for all `Shipit::Api` controllers guaranteeing that any controller-level override of `stack`/`stacks` cannot silently drop the `ApiClient` stack-scope check, plus regression tests asserting a stack-scoped client cannot read data for any other stack via every API endpoint (including `CCMenuController`).

### Proof of Concept
1. As a legitimate Shipit user with access to `stack-A`, visit the CCMenu URL feature to have `CCMenuUrlController#fetch` mint a token (`ApiClient` named "CCMenu Client", `permissions: ['read:stack']`, no `stack_id`) [8](#0-7) .
2. Using that token, call `GET /api/stacks/<owner>/<other-repo>/<other-env>/ccmenu?token=<token>` for `stack-B`, a stack the user has no access to.
3. `Api::CCMenuController#authenticate_api_client` authenticates the token fine (it's a valid `ApiClient`) [9](#0-8) ; `require_permission :read, :stack` passes because the token has the `read:stack` permission string; and `stack` resolves `stack-B` directly via `Stack.from_param!`, bypassing any stack_id scoping [10](#0-9) .
4. The response renders `stack-B`'s latest deploy/rollback status, name, and build info — data the user was never authorized to see through this token.

Note: I was unable to fully verify from the index whether any additional guard exists elsewhere (e.g., a global `before_action` that re-validates `params[:stack_id]` against `current_api_client.stack_id` for all Api controllers) beyond what's shown in `base_controller.rb`; the codebase search did not surface one. If such a guard exists outside the indexed portions, it would need to be confirmed via a full repository check.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
