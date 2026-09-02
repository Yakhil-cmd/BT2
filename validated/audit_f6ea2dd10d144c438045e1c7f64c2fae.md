## Title
Cross-stack read of deploy/lock state via stack-scoped API token in `Api::CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts a stack-scoped `ApiClient` (one created with a `stack_id`) to only the stack it is bound to, by resolving stacks through the `stacks`/`stack` helpers, which filter by `current_api_client.stack_id`. `Api::CCMenuController` overrides `#stack` to bypass this scoping entirely, resolving the target stack directly from the URL parameter with no relation to the authenticated client's authorized stack.

### Finding Description
`Api::BaseController` defines the authorization-scoped stack lookup: [1](#0-0) 

This means any `ApiClient` created with a `stack_id` (e.g. `here_come_the_walrus` in the fixtures, `permissions: read:stack`, `stack: shipit`) is bound to *only* that stack: `current_api_client.stack_id?` is true, so `stacks` becomes `Stack.where(id: current_api_client.stack_id)`, and every controller that uses `stack`/`stacks` for lookup (`StacksController`, `HooksController`, `TasksController`, etc.) enforces that the token can only touch its own stack.

`Api::CCMenuController`, however, overrides `#stack` to bypass this scoping check entirely: [2](#0-1) 

It resolves the stack directly with `Stack.from_param!(params[:stack_id])`, never consulting `stacks`/`current_api_client.stack_id`. The controller still requires the `read:stack` permission scope via `require_permission :read, :stack`, but that check only validates the client has the `read:stack` capability string in its `permissions` array — it says nothing about *which* stack the token is scoped to.

The binding that should hold is: **stack a token authorizes == stack a token can touch**. Before the request, an attacker who obtains/legitimately holds a stack-scoped read-only API token (bound to stack A) is authorized only for stack A. After hitting `GET /api/stacks/*stack_id/ccmenu` with `stack_id` set to stack B, the controller renders stack B's CI/deploy status — a stack the token was never authorized for — because `#stack` never checks `current_api_client.stack_id`.

### Impact Explanation
This yields unauthenticated (from the perspective of stack B) read of stack state: deploy status (`lastBuildStatus`), lock state, and activity for any stack in the installation, exposed to a holder of a token that was only meant to see one stack. This matches the "High" impact category: unauthenticated read of stack state/deploy output, achieved by escalating a scoped token's effective scope to the entire installation.

### Likelihood Explanation
Likelihood is meaningful because stack-scoped, read-only API tokens are a documented, intended feature (see `ApiClient#stack_id`/`belongs_to :stack, optional: true` and the `here_come_the_walrus` fixture pattern used precisely to restrict a client to one stack) — these tokens are handed out for narrower trust levels (e.g. embedding in CI dashboards, CCMenu tools) specifically so the holder cannot see other stacks. No privileged account or additional secret is needed beyond the already-issued scoped token; only a change of the `stack_id` URL segment is required.

### Recommendation
Make `Api::CCMenuController#stack` go through the same scoped lookup as the rest of the API (`stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`), so stack-scoped tokens are restricted consistently across all API endpoints.

### Proof of Concept
1. Admin creates a stack-scoped, read-only `ApiClient` bound to Stack A (`stack_id` set, `permissions: ['read:stack']`), analogous to fixture `here_come_the_walrus`.
2. Attacker (or legitimate holder of that token, e.g. a CCMenu dashboard for Stack A) sends:
   `GET /api/stacks/<owner>/<repo>/<environment-of-stack-B>/ccmenu` using the Stack-A-scoped token's basic-auth credentials.
3. `Api::BaseController#authenticate_api_client` succeeds (token is valid) and `require_permission :read, :stack` passes (the client does have `read:stack`).
4. `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])`, resolving Stack B directly, ignoring `current_api_client.stack_id`.
5. Response renders Stack B's CCMenu XML (`lastBuildStatus`, lock state, etc.), even though the token is only authorized for Stack A.

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
