### Title
Authorization bypass in `CCMenuController` allows a stack-scoped API token to read the CI/deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper used by every other `Api::BaseController` subclass, resolving the target stack directly from the URL instead of scoping it to the stack authorized by the presented `ApiClient` token. This breaks the equality the rest of the API enforces: *the stack a token authorizes* must equal *the stack the request touches*.

### Finding Description
`Shipit::Api::BaseController` centralizes stack resolution and scoping: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the token is stack-scoped, and every controller that relies on `stack` (e.g. `Api::TasksController`, `Api::MergeRequestsController`, `Api::StacksController#show`) inherits this enforcement, so a token scoped to stack A cannot address stack B via `params[:id]`/`params[:stack_id]`.

`Api::CCMenuController`, however, defines its own `stack` method that bypasses this scoping entirely: [2](#0-1) 

`Stack.from_param!(params[:stack_id])` resolves against the global `Stack` relation, ignoring `current_api_client.stack_id`. `require_permission :read, :stack` only confirms the token *has* the `read:stack` permission bit; it does not confirm the token is authorized for *this particular* stack — that check is normally implicit in the `stacks.from_param!` scoping, which `CCMenuController` skips.

The `authenticate_api_client` override further shows the endpoint is meant to be reachable with any valid token, including query-string tokens, not just tokens created specifically for CCMenu: [3](#0-2) 

The equality broken: `current_api_client.stack_id (the stack a token authorizes)` ≠ `stack (the stack a request touches)`, exactly the class of "authorised-vs-touched" binding highlighted in the report's bug-class hint, applied here to the CCMenu endpoint instead of the origin/hostname check in the original report.

### Impact Explanation
Any holder of a legitimately issued, stack-scoped `ApiClient` token with `read:stack` permission (for their own stack) can supply a different `stack_id` in the URL and retrieve build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, `webUrl`) for a stack they were never authorized to see. This is an authorization-scope escalation into `Shipit::Stack` state disclosure across stacks/repositories that the token owner does not control, matching the "High - unauthenticated read of stack state" impact category (the request is authenticated, but with a token whose scope explicitly excludes the accessed stack, i.e., unauthorized read).

### Likelihood Explanation
Exploitation only requires possession of any valid, stack-scoped `ApiClient` token with `read:stack` permission — a routine credential many integrators legitimately hold (e.g. a CI dashboard or a per-repo CCMenu client) — and knowledge/guessing of the victim stack's `owner/repo/environment` path segment, which is generally discoverable (repo names are public/known). No signature forgery, GitHub credentials, or privileged account are required, only a normal, narrowly-scoped API token.

### Recommendation
Change `Api::CCMenuController#stack` to resolve the stack through the scoped `stacks` relation inherited from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!`, so stack-scoped tokens cannot address stacks outside their authorized `stack_id`.

### Proof of Concept
1. Create two stacks: `victim-org/private-app/production` (Stack A) and `attacker-org/public-app/production` (Stack B).
2. Issue an `ApiClient` scoped to Stack B (`stack_id = B.id`) with `permissions: ['read:stack']` (this is a normal, legitimately-issued token for the attacker's own stack).
3. As the attacker, request:
   `GET /ccmenu/victim-org/private-app/production?token=<token_scoped_to_B>`
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])`, returning Stack A regardless of the token's `stack_id` restriction, and the controller renders Stack A's CCMenu XML (`lastBuildStatus`, lock state, `webUrl`, etc.) - disclosing state of a stack the token was never authorized to access.

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
