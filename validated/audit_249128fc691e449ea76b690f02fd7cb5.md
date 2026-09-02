This confirms the vulnerability. `BaseController#stack` at [1](#0-0)  scopes lookups through `stacks`, which restricts to `current_api_client.stack_id` when the `ApiClient` is stack-scoped. `Api::StacksController#stack` correctly reuses this scoped `stacks.from_param!` lookup at [2](#0-1) . However, `Api::CCMenuController#stack` bypasses this scoping entirely, calling `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table at [3](#0-2) , and `require_permission :read, :stack` only checks that the permission name `"read:stack"` is present via `ApiClient#check_permissions!`, without checking `stack_id` at all [4](#0-3) .

### Title
Stack-scoped API token authorizes cross-stack read via `CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
An `ApiClient` token created with `stack_id` set (i.e., authorized to read only one specific stack) can be used through `Api::CCMenuController#show` to read the CI/deploy status (CCTray XML) of **any** stack in the installation, not just the one it was scoped to.

### Finding Description
`ApiClient` records can be scoped to a single stack via `stack_id` [5](#0-4) . The intended enforcement of that scope lives in `Api::BaseController#stacks`/`#stack`, which restricts the queryable set of stacks to `Stack.where(id: current_api_client.stack_id)` before resolving `params[:stack_id]` [1](#0-0) . `Api::StacksController` relies on this exact scoped helper [2](#0-1) .

`Api::CCMenuController`, however, defines its own `stack` method that resolves `params[:stack_id]` against the unscoped `Stack` model directly, ignoring `current_api_client.stack_id` entirely [3](#0-2) . The only authorization check applied is `require_permission :read, :stack`, which merely checks that the token's `permissions` array contains the string `"read:stack"` — it never compares `operation`/`scope` against a specific record [4](#0-3) .

This breaks the binding: `stack a token authorizes == stack it touches`. Before: a stack-scoped token with `read:stack` could only reach the stack matching its `stack_id` through any endpoint using the shared `stack`/`stacks` helpers. After: the same token, when pointed at `Api::CCMenuController#show` with an arbitrary `stack_id` in the URL, reaches any stack in the deployment, because that controller's `stack` method never applies the `stacks` scope.

### Impact Explanation
This is an unauthenticated-scope escalation: a low-privilege, single-stack-scoped API token (e.g., the "CCMenu Client" tokens created automatically and narrowly by `CCMenuUrlController#client` with only `read:stack` permission and bound to one stack [6](#0-5) ) can be replayed against `/api/1/stacks/:stack_id/cctray.xml` for any other stack to read that stack's deploy/rollback status, last build label, and activity — data the token holder was never authorized to see. This matches the "unauthenticated read of stack state" High-impact category, since it defeats the per-stack authorization boundary the engine otherwise enforces uniformly.

### Likelihood Explanation
Likelihood is high for anyone holding a legitimate stack-scoped CCMenu token (these tokens are handed out via `CCMenuUrlController#fetch` and embedded in query strings for third-party CI dashboard tools, so they are relatively widely distributed and lower-trust by design). No privileged access, session, or webhook secret is required — only a token meant for one stack, plus knowledge/guessing of another stack's `:stack_id` param (stack slugs, e.g. `owner/repo/environment`, are not secret).

### Recommendation
Change `Api::CCMenuController#stack` to resolve `params[:stack_id]` through the shared, scope-aware `stacks` helper (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so stack-scoped tokens cannot escape their `stack_id` binding. Additionally, consider having `ApiClient#check_permissions!` (or a dedicated method) validate the target record's id against `stack_id` whenever the client is stack-scoped, so any future controller cannot regress this check by defining its own unscoped `stack` method.

### Proof of Concept
1. Create/obtain an `ApiClient` token scoped to `stack_id: A` with permission `read:stack` (e.g., via `CCMenuUrlController#fetch` on stack A, which creates such a client automatically [7](#0-6) ).
2. Using HTTP Basic auth with that token, request `GET /api/1/stacks/<stack-B-param>/cctray.xml` where stack B ≠ stack A.
3. `authenticate_api_client` succeeds (valid token) and `require_permission :read, :stack` passes because the token's `permissions` includes `"read:stack"` [4](#0-3) .
4. `Api::CCMenuController#stack` resolves stack B directly via `Stack.from_param!`, bypassing the `stack_id` scope [3](#0-2) , and the response renders stack B's deploy status — data outside the token's authorized stack.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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
