### Title
Stack-scoped API tokens can read the CI status of any stack via the CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
Shipit's API layer binds an `ApiClient` token to a specific stack via `ApiClient#stack_id`, and `Api::BaseController#stack` enforces that scoping by resolving stacks through the `stacks` helper before looking one up by param. `Api::Api::CCMenuController` overrides `#stack` and bypasses that scoping entirely, breaking the equality "stack a token authorizes == stack it touches."

### Finding Description
`Api::BaseController` defines the trust boundary between a token and the stack(s) it may act on: [1](#0-0) 

`stacks` is restricted to `current_api_client.stack_id` when the client is scoped, and `stack` is derived from that restricted relation. Any controller that inherits this `stack` method (e.g. the stacks, tasks, deploys, hooks controllers) is therefore constrained to the stack(s) the token authorizes.

`Api::CCMenuController`, however, redefines `stack` to look the record up directly on the unscoped `Stack` model, ignoring `current_api_client.stack_id`: [2](#0-1) 

The only authorization check performed is `require_permission :read, :stack`, which merely verifies the token carries the generic `read:stack` permission string — it never verifies the requested `stack_id` matches `current_api_client.stack_id`: [3](#0-2) 

Tokens intended to be scoped to a single stack are routinely minted this way through `CCMenuUrlController`, which creates a client scoped only to the requesting stack and hands the caller a URL embedding that token: [4](#0-3) 

Because `Api::CCMenuController#stack` does not reuse the inherited `stacks`/`stack` scoping, a holder of such a "CCMenu Client" token — meant only to read one stack's status — can supply any other stack's id in `GET /api/stacks/:stack_id/ccmenu` and read that stack's build/lock status instead. The equality that should hold, `current_api_client.stack_id == params[:stack_id]` (or "unscoped"), is never checked on this path.

### Impact Explanation
This crosses the "stack a token authorizes vs stack it touches" boundary named in scope: a token minted for stack A discloses stack B's CI/lock/deploy state (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock status) via the CCMenu XML feed. This is an unauthenticated-scope escape resulting in unauthorized read of another stack's state, matching the High-impact criterion "unauthenticated read of stack state."

### Likelihood Explanation
Any actor in possession of a legitimately-issued, narrowly-scoped CCMenu token (these tokens are embedded in plain URLs distributed to CI dashboard tools, per `CCMenuUrlController`) can trivially exploit this by changing the `stack_id` segment of the request path — no additional privilege, secret, or session is required beyond the token they already legitimately hold for a different stack.

### Recommendation
Have `Api::CCMenuController#stack` reuse the inherited, scope-aware `stacks` relation from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the `current_api_client.stack_id` restriction is enforced consistently across all API controllers.

### Proof of Concept
1. Stack A's operator visits `/ccmenu/*stack_a_id`, causing `CCMenuUrlController#fetch` to mint an `ApiClient` scoped to `stack: stack_a` with `permissions: ['read:stack']`, and receives a URL like `https://shipit.example.com/api/stacks/org/repo-a/production/ccmenu?token=<tokenA>`.
2. An attacker who obtains `tokenA` (e.g., from a shared CI dashboard config) issues:
   `GET /api/stacks/org/repo-b/production/ccmenu?token=<tokenA>`
3. `Api::CCMenuController#authenticate_api_client` accepts `tokenA` as valid, `require_permission :read, :stack` passes because the token has `read:stack`, and `#stack` resolves `Stack.from_param!('org/repo-b/production')` — an entirely different stack than the one `tokenA` was scoped to.
4. The response discloses `repo-b`'s build status, lock state, and last build label, even though `tokenA.stack_id` points to `repo-a`.

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
