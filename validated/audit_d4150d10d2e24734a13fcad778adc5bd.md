### Title
Cross-stack read of deploy state via CCMenu endpoint bypasses per-stack token scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the inherited, scope-enforcing `stack` accessor with an unscoped lookup, breaking the binding between "the stack an `ApiClient` token is authorized for" and "the stack the request actually reads." A token that is scoped to Stack A (via `ApiClient#stack_id`) can be replayed against `GET /api/stacks/:stack_id/ccmenu` with an arbitrary Stack B identifier and will successfully read Stack B's deploy state.

### Finding Description
`Api::BaseController` establishes the intended equality binding: a scoped `ApiClient` may only resolve stacks from its own scope. [1](#0-0) 

This binding is: `current_api_client.stack_id == stack.id` whenever `current_api_client.stack_id?` is true, enforced by scoping the lookup through `stacks.from_param!` rather than `Stack.from_param!`.

`Api::CCMenuController`, however, redefines `stack` to bypass this scope entirely: [2](#0-1) 

`show` then calls this unscoped `stack` to render deploy status: [3](#0-2) 

The only authorization gate on this action is `require_permission :read, :stack`, which merely checks that the string `"read:stack"` is present in the client's `permissions` array — it does not check *which* stack the permission was granted for: [4](#0-3) 

`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true`, and this is exactly how CCMenu tokens are minted for regular users — `CCMenuUrlController` creates (or reuses) a `read:stack`-permissioned `ApiClient` per user and embeds its `authentication_token` in query-string URLs meant for third-party CI status tools: [5](#0-4) 

Because `CCMenuController#authenticate_api_client` accepts the token from `params[:token]` (a URL query string, not a `Basic` header, and thus far more likely to leak via logs, referrers, browser history, or being pasted into a CI dashboard), and the `stack` method it uses ignores the client's own `stack_id`, anyone in possession of *any* valid `read:stack` CCMenu token — even one minted for their own, unprivileged stack — can supply a different `stack_id` in the URL and read another stack's deploy/rollback status and history.

Before vs. after the token's original binding is honored:
- Intended: `token.stack_id == requested_stack.id` (or `token.stack_id` unset ⇒ global `read:stack`).
- Actual in `CCMenuController#show`: `requested_stack = Stack.from_param!(params[:stack_id])` with no relation to `token.stack_id`.

### Impact Explanation
This grants unauthorized, unattenuated read access to another stack's deploy state (last deploy id, status, timestamps, stack name) to any holder of a legitimate, narrowly-scoped `read:stack` CCMenu token. This matches the specified High-severity impact class: "unauthenticated read of stack state ... or deploy output" via escalation past the intended per-stack authorization scope — the token authenticates the request, but the scope check that should bind it to one stack is skipped for this specific controller action, unlike every other `Api::BaseController` subclass.

### Likelihood Explanation
High. Exploitation requires only a single valid CCMenu token (one legitimately obtained via the normal `ccmenu_url#fetch` flow for any stack the attacker can already view) and knowledge/guessing of another stack's `owner/repo/environment` identifier (these are visible in Shipit's own UI/URLs and are not secret). No privileged account, GitHub App key, webhook secret, or write access is needed — only a routine, low-privilege CCMenu read token that a normal Shipit user already holds for their own stack.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, scoped `Api::BaseController#stack` (`stacks.from_param!(params[:stack_id])`) so CCMenu lookups honor `current_api_client.stack_id` exactly like every other API controller.

### Proof of Concept
1. As a normal user, visit `GET /ccmenu/*stack_id` (`CCMenuUrlController#fetch`) for `Stack A` you legitimately have access to; this creates/returns a `read:stack`-permissioned `ApiClient` scoped to `Stack A` and returns a URL containing `?token=<A's token>`.
2. Take the returned token and issue `GET /api/stacks/<owner>/<name>/<environment_of_stack_B>/ccmenu?token=<A's token>` for a different `Stack B` that the token was never scoped to.
3. `CCMenuController#authenticate_api_client` accepts the token (it is valid and has `read:stack`), and `CCMenuController#stack` resolves `Stack B` via unscoped `Stack.from_param!`, bypassing the `current_api_client.stack_id` check in `BaseController#stacks`.
4. The response renders Stack B's `deploys_and_rollbacks.last` deploy status/XML, disclosing deploy state the token holder was never authorized to see.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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
