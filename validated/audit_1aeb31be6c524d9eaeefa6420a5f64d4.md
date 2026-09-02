### Title
CCMenu API token scoped to one stack can read the CI/deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` authorizes requests purely by checking that the presented `ApiClient` has the generic `read:stack` permission, but then loads the target `Stack` directly from the URL parameter instead of from the client's authorized stack scope. This breaks the equality "stack a token authorizes == stack the token touches," the exact binding class called out for this bug family, letting a token minted for stack A read the deploy state of any other stack B.

### Finding Description
Every other authenticated API endpoint resolves stacks through the scoped helper defined in `BaseController`: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is stack-scoped, and `stack` resolves `params[:stack_id]` only within that restricted set.

`Api::CCMenuController`, however, overrides stack resolution and bypasses this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, ignoring `current_api_client.stack_id`. The only gate is `require_permission :read, :stack`, which merely checks the string `"read:stack"` is present in `ApiClient#permissions`: [3](#0-2) 

This check never verifies which stack the permission applies to; that binding exists only via `belongs_to :stack, optional: true` and is enforced solely through the `stacks`/`stack` helpers in `BaseController` — helpers this controller doesn't use.

Making this worse, the token minted by `CCMenuUrlController` for "this stack" doesn't even set the `stack` association when creating the `ApiClient`: [4](#0-3) 

`find_or_create_by!(creator: current_user, name: 'CCMenu Client')` matches only on `creator` and `name`; `stack:` is never passed to `find_or_create_by!` (only to `create_with`, which is ignored once the record already exists for that creator). So even the intended "one client per stack" design collapses to one shared, unscoped `ApiClient` per user across every stack they've ever generated a CCMenu URL for.

### Impact Explanation
Any user who can view at least one stack's overview page can trigger `CCMenuUrlController#fetch` to obtain a signed `read:stack` API token. Because `Api::CCMenuController#stack` ignores the client's `stack_id` binding, that token can be replayed against `/api/1/stacks/:stack_id/ccmenu.xml` for arbitrary `stack_id` values, disclosing deploy/CI status (`stack.deploys_and_rollbacks.last`) for stacks the user was never authorized to see — including stacks backed by repositories outside the user's `Shipit.github_teams` authorization. This is an authorization-scope escalation matching the rules' "escalation into `Shipit.github_teams` authorization" / "unauthenticated read of stack state" impact class.

### Likelihood Explanation
Any authenticated Shipit user can obtain the token from the UI without any special permission (`CCMenuUrlControllerTest` shows only `session[:user_id]` is required), and the exploit is a single unauthenticated-by-repo GET request with a different `stack_id` — no race condition, no admin cooperation, and no additional secret required.

### Recommendation
- In `Api::CCMenuController`, resolve the stack through the scoped `stacks` helper (`stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!`.
- In `CCMenuUrlController#client`, include `stack:` in the `find_or_create_by!` lookup keys (not just `create_with`) so a distinct, properly-scoped `ApiClient` is created per stack.
- Add a regression test asserting that a CCMenu token minted for stack A returns 403/404 when used against stack B's `ccmenu.xml`.

### Proof of Concept
1. As any logged-in Shipit user with access to Stack A, visit Stack A's overview page and let it call `GET /stacks/:A/ccmenu_url` → returns `ccmenu_url` containing a `token` for an `ApiClient` with `permissions: ['read:stack']`.
2. Take that `token` and call `GET /api/1/stacks/:B/ccmenu.xml?token=<token>` where `B` is a stack the user cannot otherwise access (e.g., a private/restricted repository's stack).
3. `authenticate_api_client` succeeds (valid signed token), `require_permission :read, :stack` passes (client has `read:stack`), and `stack` resolves `B` directly from `params[:stack_id]` with no scoping check — the response discloses Stack B's latest deploy/CI status.

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
