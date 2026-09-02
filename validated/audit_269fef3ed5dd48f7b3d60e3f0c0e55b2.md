### Title
Cross-stack unauthenticated read of build status via CCMenu API token scope bypass - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup used by every other Stack-scoped API controller to bypass the `ApiClient#stack_id` restriction that is supposed to bind a token to a single stack. This lets any valid `ApiClient` token authenticate to the CCMenu endpoint for **any** stack in the installation, not just the stack it was minted for.

### Finding Description
`Shipit::Api::BaseController` scopes stack lookups to the `ApiClient`'s own `stack_id` when one is set: [1](#0-0) 

This is the binding that authorizes an `ApiClient` token for one specific stack: `stacks = current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `stack = stacks.from_param!(params[:stack_id])`. Every other API controller (`Api::TasksController`, `Api::StacksController`, etc.) inherits this and is correctly bound: `token.stack_id == stack.id` (when the token is stack-scoped).

`Api::CCMenuController`, however, redefines `stack` to bypass that scoping entirely and query the global `Stack` model directly: [2](#0-1) 

It also implements its own `authenticate_api_client` that accepts the token from `params[:token]` (query string) instead of only via `Authorization` header, but that path still simply calls `ApiClient.authenticate(token)`, which only verifies the message-signature and returns the `ApiClient` row — it never re-checks `stack_id`: [3](#0-2) [4](#0-3) 

The permission check performed via `require_permission :read, :stack` only validates that the permissions array on the `ApiClient` contains the literal string `"read:stack"` — it is not scoped to which stack is being requested: [5](#0-4) 

So the equality that should hold — `current_api_client.stack_id == requested_stack.id` (when the client is stack-scoped) — is broken specifically in `CCMenuController#stack`, because it resolves the stack from the raw `Stack` relation instead of from the caller's scoped `stacks` method.

### Impact Explanation
A `Shipit::ApiClient` token that was intentionally minted and scoped to a single stack (e.g. via `CCMenuUrlController#client`, which creates a `read:stack`-only, stack-scoped client for embedding in third-party CI dashboard tools: `app/controllers/shipit/ccmenu_url_controller.rb:15-18`) can be replayed against the CCMenu endpoint for **any other stack id** in the Shipit installation, returning that other stack's name, lock state, last deploy id/time/status, and web URL: [6](#0-5) 

This is an unauthenticated (with respect to the target stack) read of stack/deploy state that the token holder was never granted, meeting the "High — unauthenticated read of stack state, task streams or deploy output" bucket. Because CCMenu tokens are commonly embedded in third-party build-monitor tools/URLs (lower operational secrecy than the primary API token), and the bypass requires no special privilege beyond possessing any one valid stack-scoped token, this is a genuine cross-repository information-disclosure vector distinct from normal API usage.

### Likelihood Explanation
Likelihood is Medium: exploitation requires possession of any single valid CCMenu/API token (these are routinely distributed to embed in dashboards, so they are more likely to leak or be shared than the primary Shopify GitHub session), and the attack is a single unauthenticated (no header/auth needed beyond the token) GET request with an arbitrary `stack_id` — no additional guessing beyond enumerable stack slugs (`owner/repo/environment`), which are not secret.

### Recommendation
Remove the `stack` override in `Api::CCMenuController`, or explicitly re-check the scoping invariant there: resolve the stack via the same `stacks` (client-scoped) relation used in `BaseController`, i.e. `stacks.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` cannot be used to read data for stacks outside its `stack_id`.

### Proof of Concept
1. Create (or obtain) a stack-scoped `ApiClient` for Stack A via `CCMenuUrlController#client` (or any UI flow that produces a CCMenu URL), e.g. `read:stack` permission with `stack_id = A.id`.
2. Note its `authentication_token` (embedded in the generated CCMenu URL, e.g. `.../api/stacks/A/ccmenu?token=<TOKEN>`).
3. Issue `GET /api/stacks/<STACK_B_PARAM>/ccmenu?token=<TOKEN>` where `STACK_B_PARAM` refers to a different stack B that the token was never scoped to.
4. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (unscoped) instead of `stacks.from_param!(...)` (client-scoped), the request succeeds with `200 OK` and returns Stack B's `name`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` — data the token was never authorized to access.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
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

**File:** app/views/shipit/ccmenu/project.xml.builder (L6-15)
```text
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
```
