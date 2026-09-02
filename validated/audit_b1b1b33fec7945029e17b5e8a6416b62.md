### Title
API-token stack scope bypass in CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper defined by `Shipit::Api::BaseController` in a way that skips the per-`ApiClient` stack-scoping check, letting any authenticated API token read CI/build status for stacks it was never authorized to touch.

### Finding Description
`Shipit::Api::BaseController` deliberately restricts which stacks an `ApiClient` may resolve via the `stacks`/`stack` helpers: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This is the binding the engine relies on: **the stack a token authorizes == the stack a controller touches**, enforced by scoping `Stack` lookups through `stacks` whenever `current_api_client.stack_id` is set (this is exactly the mechanism exercised in `test/controllers/api/stacks_controller_test.rb`'s `"an api client scoped to a stack will only see that one stack"` test).

`Shipit::Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

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

Because `Stack.from_param!` is called directly on the unscoped `Stack` model instead of on the `stacks` collection, `current_api_client.stack_id` is never consulted. The controller's `require_permission :read, :stack` before-action only calls `current_api_client.check_permissions!('read', 'stack')`, which merely checks that the string `"read:stack"` is present in the client's `permissions` array — it never checks *which* stack the permission applies to: [3](#0-2) 

So the equality that should hold — `token.authorized_stack_id == params[:stack_id]` (when the token is scoped) — is broken specifically on this controller: any token with the generic `read:stack` permission, whether or not it is scoped to one particular stack via `ApiClient#stack_id`, can supply an arbitrary `stack_id` and receive that other stack's CI project data.

### Impact Explanation
This is an authorization-boundary crossing: it allows a caller in possession of a stack-scoped API token (deliberately restricted by an operator to a single stack) to read build/CI state — name, last build status/label/time, web URL — for **any** other stack in the installation, not just the one the token was authorized for. This matches the in-scope High-severity criterion "escalation into `Shipit.github_teams` authorization[...] or unauthenticated read of stack state, task streams or deploy output": here a token authorized for stack A is used to read stack state for stack B, which the operator explicitly intended to prevent by setting `ApiClient#stack_id`.

### Likelihood Explanation
Likelihood is high for any deployment that issues scoped `ApiClient` tokens (i.e., sets `stack_id` on the `ApiClient`, the documented mechanism for restricting a third-party integration to one stack). The attacker only needs: (1) a valid, currently-scoped API token with `read:stack` permission (already a normal, unprivileged credential handed to CI dashboards/status widgets), and (2) knowledge/guess of another stack's `to_param` (its owner/repo/environment/branch identifiers, typically discoverable/guessable since they mirror GitHub repo names). No elevated privileges, session, or additional secrets are required beyond the token that was already meant to be limited to one stack.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection exactly like `BaseController#stack` does, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the invariant that a stack-scoped token can never resolve a `Stack` outside `current_api_client.stack_id`.

### Proof of Concept
1. Operator creates an `ApiClient` "ci-badge-bot" scoped to `stack_id = A.id` with permission `read:stack`, and hands its `authentication_token` to a third party to embed a CI badge only for stack A.
2. That third party (or anyone who obtains the token, e.g. from a public badge URL/CI config) issues:
   ```
   GET /api/stacks/<owner-B>/<repo-B>/<env-B>/cc.xml?token=<ci-badge-bot-token>
   ```
   where `owner-B/repo-B/env-B` is a *different* stack B that the token was never authorized to see.
3. Because `CCMenuController#stack` calls `Stack.from_param!` directly (not `stacks.from_param!`), `current_api_client.stack_id` is never checked; `check_permissions!('read', 'stack')` passes because the token simply has `read:stack` in its permission list.
4. The response renders stack B's `shipit/ccmenu/project` XML (name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) even though the token was scoped exclusively to stack A — confirmed by contrasting with `test/controllers/api/stacks_controller_test.rb`'s scoped-token test, which shows the same token/scoping mechanism correctly restricting `Api::StacksController#index` to the assigned stack only.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
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
