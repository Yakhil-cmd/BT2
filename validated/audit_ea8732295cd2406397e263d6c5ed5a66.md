This confirms the vulnerability. `BaseController#stacks` (in `app/controllers/shipit/api/base_controller.rb:74-75`) is the scoping mechanism that restricts an `ApiClient` to only the `Stack` it was created for when `stack_id?` is set. `BaseController#stack` (line 78-80) correctly funnels through this scoped `stacks` relation. However, `CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) overrides this with `Stack.from_param!(params[:stack_id])`, querying the unscoped `Stack` table directly, completely bypassing the `current_api_client.stack_id` restriction.

Since `CCMenuController` only checks the generic permission `read:stack` (`require_permission :read, :stack`, delegating to `ApiClient#check_permissions!` in `app/models/shipit/api_client.rb:38-45`, which only checks the `permissions` array, never `stack_id`), any token scoped to one stack (e.g. the `here_come_the_walrus` fixture scoped to `stack: shipit` in `test/fixtures/shipit/api_clients.yml:12-17`) can be replayed against `GET /api/:stack_id/ccmenu.xml?token=...` for **any other stack_id** and successfully retrieve that stack's deploy/build status.

### Title
Stack-scoped API token bypasses stack authorization in CCMenuController - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`CCMenuController` authenticates `ApiClient` tokens via `params[:token]` and enforces only the generic `read:stack` permission, but resolves the target `stack` via the unscoped `Stack.from_param!(params[:stack_id])` instead of the stack-scoped `stacks` helper used everywhere else in `Api::BaseController`. This breaks the equality "stack a token authorizes == stack a token touches," letting a token scoped to stack A read stack B's CI/build status.

### Finding Description
`Api::BaseController` implements per-token stack scoping: [1](#0-0) . This is the binding that every other API controller (e.g. `StacksController`, `TasksController`, etc., via `stacks`/`stack`) relies on to ensure a stack-scoped `ApiClient` (`ApiClient#stack_id`, `app/models/shipit/api_client.rb:8`) cannot act on stacks outside its assigned `stack`.

`CCMenuController` overrides `stack` and re-implements token authentication independently: [2](#0-1) . It calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, never touching `current_api_client.stack_id`. The only authorization check performed is `require_permission :read, :stack` at line 6, which resolves to `ApiClient#check_permissions!` — a check against the generic `permissions` array only: [3](#0-2) . It never considers `stack_id`.

Consequently, for any `ApiClient` record that has `read:stack` in its `permissions` (which is the default/only meaningful permission for CCMenu use, see `CCMenuUrlController#client`, `app/controllers/shipit/ccmenu_url_controller.rb:15-18`, and the `here_come_the_walrus` fixture scoped to a single stack: [4](#0-3) ), the token's authorization is silently widened from "this one stack" to "every stack in the installation" the moment it's presented to the CCMenu endpoint.

### Impact Explanation
This is an unauthenticated-scope violation resulting in unauthorized read access to another repository/stack's deploy/build state (last build status, label, activity, web URL — see the rendered fields asserted in `test/controllers/api/ccmenu_controller_test.rb:33-39`). Per the engine's authorization model, a token minted with `stack: <specific stack>` must never be usable to read a different stack; this is exactly the "High — unauthenticated read of stack state" category, since any holder of a narrowly-scoped API token (which may be distributed to lower-trust consumers, e.g. embedded in a CI status widget URL, given it is passed as a plain query string `?token=`) gains read access across all stacks in the Shipit instance.

### Likelihood Explanation
Likelihood is high for any deployment using per-stack scoped `ApiClient` tokens (a documented, intentional use case — see `ApiClient#stack` association and the `stack_id?`-based scoping in `BaseController#stacks`). The token is passed in a URL query parameter (`?token=`) rather than only via `Authorization` header, increasing exposure (logs, referrer headers, browser history), and exploitation requires only substituting the `stack_id` path segment — no additional credentials or signature forgery needed.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited scoped `stacks` relation instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the `current_api_client.stack_id` binding enforced by `Api::BaseController#stacks`.

### Proof of Concept
1. Create (or have provisioned) a stack-scoped `ApiClient` for `stack_id = A` with `permissions: ['read:stack']` (as done by `CCMenuUrlController` / any admin issuing a scoped read-only token for stack A).
2. Obtain its `authentication_token` (e.g. via the "CCMenu URL" feature, `GET /:stack_id/ccmenu_url`, `app/controllers/shipit/ccmenu_url_controller.rb:7-11`).
3. As an unprivileged holder of that token, request a **different** stack B's CCMenu feed:
   `GET /api/<stack_B_id>/ccmenu.xml?token=<token-scoped-to-stack-A>`
4. `CCMenuController#authenticate_api_client` accepts the token (valid signature, valid `ApiClient` record). `require_permission :read, :stack` passes because the client's `permissions` includes `read:stack` regardless of which stack. `stack` resolves via `Stack.from_param!(params[:stack_id])` to stack B, unscoped. The response renders stack B's build/deploy status XML — data the token was never authorized to see.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
