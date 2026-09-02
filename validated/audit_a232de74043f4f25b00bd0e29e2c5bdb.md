### Title
Stack-scoped API tokens can read any stack's build status via CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's stack-lookup helper in a way that discards the stack scoping normally enforced for `ApiClient` tokens that are bound to a single stack, allowing such a token to read the deploy status of any stack in the installation, not just the one it was authorized for.

### Finding Description
`Shipit::Api::BaseController` binds every stack-scoped operation to the authenticated `ApiClient` via the `stacks` helper: [1](#0-0) 

`current_api_client.stack_id?` is true when an `ApiClient` (see `belongs_to :stack, optional: true` on `ApiClient`) was created scoped to a single stack — e.g. via `CCMenuUrlController#client`, which creates a `read:stack`-only client tied to one stack: [2](#0-1) 

In that case `stacks` is restricted to `Stack.where(id: current_api_client.stack_id)`, and any controller using the inherited `stack` method (`stacks.from_param!(params[:stack_id])`) cannot resolve a stack outside that scope.

However, `Shipit::Api::CCMenuController` — the controller that actually serves this scoped token's intended purpose (a per-stack CCMenu XML status feed) — redefines `stack` to bypass the scope entirely: [3](#0-2) 

The `require_permission :read, :stack` check only verifies that the `read:stack` permission bit is present on the token (`ApiClient#check_permissions!`); it never verifies that the specific `stack_id` requested matches the token's bound `stack_id`: [4](#0-3) 

This breaks the equality that the rest of the API enforces: **stack a token authorizes == stack a token touches**. For a stack-scoped token, `current_api_client.stack_id` should equal `params[:stack_id]` (resolved), but in `CCMenuController#show` the second side is resolved unconditionally against the whole `Stack` table via `Stack.from_param!(params[:stack_id])`, with no comparison back to `current_api_client.stack_id`.

The token is legitimately obtained (e.g. it was minted specifically for a public "CCMenu URL" widget for one stack and could leak via that URL/build badge), and possessing it is not equivalent to possessing a general `read:stack` credential for the whole instance — but this bug effectively upgrades it to exactly that for any stack whose slug (`repo_owner/repo_name/environment`) the token holder knows or can enumerate.

### Impact Explanation
This is an unauthenticated read of stack/task state beyond what the credential authorizes: an attacker who obtains (or is handed, per the intended use case of `CCMenuUrlController`, which purposely mints and exposes such scoped tokens) a single-stack CCMenu token can use it to read the deploy/rollback status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, etc.) of every other stack in the Shipit instance, including stacks belonging to different repositories/environments the token was never meant to see. This matches the "unauthenticated read of stack state" High-impact category, since the token's authorization boundary (one stack) is silently ignored.

### Likelihood Explanation
Likelihood is high for anyone already holding a valid CCMenu token for one stack: exploitation only requires changing the `stack_id` query parameter to another stack's slug/id and re-issuing the GET request — no additional credentials, signatures, or privileged access are required.

### Recommendation
Have `Shipit::Api::CCMenuController#stack` reuse the scoped `stacks` relation from the base controller (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so a stack-scoped `ApiClient` cannot resolve any stack outside `current_api_client.stack_id`.

### Proof of Concept
1. Create a stack-scoped API client for Stack A, e.g. via the flow in `CCMenuUrlController#client` (`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`), which sets `stack: <Stack A>`.
2. Obtain the token's `authentication_token` (as would be embedded in the generated CCMenu URL).
3. Send `GET /api/stacks/<Stack B repo_owner>/<Stack B repo_name>/<Stack B environment>/ccmenu.xml?token=<Stack-A-scoped token>` for an unrelated Stack B.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unconditionally rather than `stacks.from_param!`, the request succeeds and returns Stack B's build status even though the token is only supposed to authorize Stack A.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-22)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
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
