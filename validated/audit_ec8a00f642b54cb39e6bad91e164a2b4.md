This confirms the vulnerability. `Shipit::Api::CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) resolves the stack directly via `Stack.from_param!(params[:stack_id])`, whereas the base class's scoping method `stacks` (`app/controllers/shipit/api/base_controller.rb:74-76`) restricts the resolvable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped to a stack. CCMenuController's override bypasses that scoping entirely, and `require_permission :read, :stack` only checks that `permissions` includes `read:stack` — it never checks whether `current_api_client.stack_id` matches the requested `stack_id`.

### Title
Stack-scoped API tokens can read state of any stack via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
An `ApiClient` token created with `stack_id` set (i.e., authorized only for a single stack, as documented and tested by "an api client scoped to a stack will only see that one stack") can be replayed against the `GET /api/stacks/:stack_id/ccmenu` endpoint with a *different* `stack_id` and will successfully read that other stack's deploy/build status. The binding broken is: **stack an `ApiClient` token authorizes (`current_api_client.stack_id`) ≠ stack the token is used to touch (`params[:stack_id]` resolved via `Stack.from_param!`)**.

### Finding Description
`Shipit::Api::BaseController` establishes the intended trust boundary for scoped tokens: [1](#0-0) 
`stacks` restricts the queryable set to the client's own `stack_id` when the client is scoped, and every controller that inherits `stack` from `BaseController` (e.g. `MergeRequestsController`, `HooksController`) is constrained to that scope.

`CCMenuController`, however, overrides `stack` to bypass this scoping: [2](#0-1) 
It resolves the target stack via `Stack.from_param!(params[:stack_id])` against the entire `Stack` table, ignoring `current_api_client.stack_id`. The only guard, `require_permission :read, :stack`, calls `current_api_client.check_permissions!(:read, :stack)`, which merely checks the string `"read:stack"` is present in the token's `permissions` array: [3](#0-2) 
It never compares `stack_id` against the requested stack. `authenticate_api_client` is also overridden to authenticate via `params[:token]` (a URL query parameter) rather than only HTTP Basic auth, which is intentional (CCMenu is used by third-party polling tools), but it does not change the missing authorization check.

### Impact Explanation
This crosses a credential/repository boundary defined by `Shipit::ApiClient.stack_id`: a token that was minted (e.g., via `CCMenuUrlController#client`, which explicitly creates a `read:stack`-scoped `ApiClient` tied to one stack: `app/controllers/shipit/ccmenu_url_controller.rb:15-18`) for a single stack can be used to read `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, and lock status for any stack in the Shipit instance, including stacks the token owner/creator has no relationship to. This matches the "High" impact class of "unauthenticated read of stack state" via authorization scope escalation, since possession of any single stack-scoped token becomes equivalent to possession of an unscoped `read:stack` token for the whole instance.

### Likelihood Explanation
Exploitation only requires possessing any one valid, stack-scoped `ApiClient` token (e.g., a CCMenu token shared with a CI dashboard, distributed to a team, or leaked in a URL/log — CCMenu tokens are designed to be embedded as query strings) and knowledge/guessing of another stack's `owner/repo/environment` identifier, which is not treated as secret elsewhere in the app (stack params are visible in the UI). No write access, GitHub credentials, or session is needed.

### Recommendation
In `CCMenuController#stack`, resolve the stack through the inherited, scope-aware `stacks` collection instead of the unscoped `Stack` model, e.g. `stacks.from_param!(params[:stack_id])`, matching the behavior of every other `Api::BaseController` subclass.

### Proof of Concept
1. Create/obtain a stack-scoped API client token for `stack A` (permissions: `["read:stack"]`, `stack_id` = A's id) — this is exactly what `CCMenuUrlController#client` does when a user requests a CCMenu URL for stack A.
2. As an attacker in possession of that token, issue `GET /api/stacks/<owner>/<other-repo>/<other-env>/ccmenu?token=<tokenA>` where the path identifies stack B (any other stack in the instance).
3. Observe the request succeeds (`200 OK`) and returns stack B's XML project status (`lastBuildStatus`, `lastBuildLabel`, lock state, etc.), even though `tokenA.stack_id == A.id != B.id`.

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
