Found the analog. `Api::CCMenuController` overrides `authenticate_api_client` to accept a bare `ApiClient.authenticate(params[:token])` (a token generator that any `ApiClient`, including a stack-scoped one, can create), then resolves the target stack via `stack` using `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!` helper defined in `BaseController`.

### Title
Stack-scoped ApiClient token grants CCMenu read access to any stack via unscoped `Stack.from_param!` lookup - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`BaseController#stacks` restricts an `ApiClient` bound to a specific `stack_id` to only that stack: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) . Every controller resolving `stack` for permission-gated actions is expected to go through this scoped relation. `CCMenuController`, however, defines its own `stack` method that bypasses this scoping entirely.

### Finding Description
`Api::CCMenuController#stack` is defined as: [2](#0-1) 
This calls `Stack.from_param!` directly on the `Stack` model rather than the request-scoped `stacks` relation used elsewhere (e.g. `Api::BaseController#stack` at [3](#0-2) , and used correctly by `CommitsController`, `OutputsController`, `MergeRequestsController`, `ReleaseStatusesController`). Any valid `ApiClient` token — including one deliberately created with `stack_id` set to scope it to a single, low-sensitivity stack (e.g. the self-service `CCMenuUrlController#client`, which auto-creates an `ApiClient` scoped to one stack with `read:stack` permission at [4](#0-3) ) — is authenticated by `authenticate_api_client` in this controller via `ApiClient.authenticate(params[:token])` [5](#0-4) , which only validates the signed client id, not any stack binding [6](#0-5) . `require_permission :read, :stack` then calls `check_permissions!` which only checks the string permission `read:stack` exists on the client and never re-validates `stack_id` [7](#0-6) . Because `stack` resolves via unscoped `Stack.from_param!`, the token authorized for stack A can be replayed with an arbitrary `stack_id` param to read CCMenu build status/output for any stack B in the deployment.

This is the direct analog of the reported LpToken bug: a guard (`whenNotPaused` / here, the stack-scope check) is enforced inconsistently across code paths — present in the shared `BaseController#stack` helper but silently dropped in one controller's local override — breaking the binding "stack a token authorizes == stack a token can touch."

### Impact Explanation
This yields unauthenticated read of another stack's build/deploy state (last build status, label, activity, web URL) beyond the token's authorized scope, matching the High-severity category "unauthenticated read of stack state ... deploy output" via a `stack_id`-scoped token that should not have visibility into other stacks.

### Likelihood Explanation
Any holder of a valid, narrowly-scoped `ApiClient` token (routinely distributed for self-service integrations such as CCMenu widgets, per `CCMenuUrlController`) can trivially trigger this by changing the `stack_id` route/query parameter — no additional privilege, secret, or session is required beyond the token itself, which the attacker already legitimately possesses for their own stack.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped relation, consistent with the rest of the API controllers:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
where `stacks` is the `BaseController#stacks` helper that filters by `current_api_client.stack_id` when present.

### Proof of Concept
1. Visit any stack's CCMenu URL to obtain a stack-scoped token, e.g. via `CCMenuUrlController#fetch`, which creates/returns an `ApiClient` with `permissions: %w[read:stack]` and `stack: <stack A>` [4](#0-3) .
2. Call `GET /api/stacks/:owner/:repo_B/:env_B/ccmenu.xml?token=<token-for-stack-A>`, substituting a different stack B's `stack_id` param.
3. `authenticate_api_client` accepts the token (only validates signature/id) [5](#0-4) ; `require_permission :read, :stack` passes because the client has `read:stack` regardless of which stack [7](#0-6) ; `stack` resolves stack B via unscoped `Stack.from_param!` [2](#0-1) .
4. Response returns stack B's build status/activity, which the token was never authorized to see.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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
