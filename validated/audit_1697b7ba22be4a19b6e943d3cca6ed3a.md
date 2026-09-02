### Title
CCMenu API token scope bypass allows reading arbitrary stack status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The CCMenu status endpoint issues a per-user, read-only `ApiClient` token intended to expose a single stack's build/deploy status to external CI dashboards, but the controller resolves the target stack independently of the token's authorized scope. Any holder of a CCMenu token can substitute an arbitrary `stack_id` and read status for any stack in the installation, breaking the binding "the stack a token authorises" versus "the stack it touches" — the same class of bug as the reported `getGuardedValue`/threshold issue, where a check that should gate access to a specific scope is silently bypassed and a value for an unauthorized/unintended target is returned as if it were valid.

### Finding Description
`Shipit::CCMenuUrlController#fetch` mints (or reuses) an `ApiClient` scoped to the current user with `read:stack` permission and **no `stack` association**: [1](#0-0) 

Because the resulting token has `stack_id` nil, `ApiClient#check_permissions!` only checks the `read:stack` permission bit and never restricts which stack the token may query: [2](#0-1) 

`Shipit::Api::BaseController` normally enforces per-token stack scoping through its `stacks`/`stack` helpers (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`): [3](#0-2) 

However `Shipit::Api::CCMenuController` overrides `stack` and resolves it directly from the request parameter, completely bypassing the scoped lookup: [4](#0-3) 

The equality that should hold is: `stack the token authorizes == stack the token touches`. Before the request, the token is only ever handed out embedded in a URL for one specific stack (`api_stack_ccmenu_url(stack_id: stack.to_param)`), so the implicit trust boundary is "this token reads status for stack X". After the request, because `CCMenuController#stack` ignores `current_api_client.stack_id` and reads `params[:stack_id]` verbatim, the token actually authorizes reading `Stack.from_param!(ANY_ID)` — any stack in the deployment, not just X.

### Impact Explanation
CCMenu tokens are explicitly designed to be embedded in URLs handed to third-party CI status tools/dashboards (often displayed as build badges, sometimes on less-trusted surfaces). An attacker who observes or obtains one such token for a low-sensitivity stack can reuse it — simply by changing the `stack_id` path segment — to read build/deploy status (`deploys_and_rollbacks`, running/ended state) of every other stack managed by that Shipit instance, including stacks that were never intended to be exposed this way. This is an unauthorized read of stack state via a credential that has escaped its intended authorization scope, which matches the "High — unauthenticated/unauthorized read of stack state" impact class.

### Likelihood Explanation
Exploitation only requires knowledge of a single valid CCMenu token (a URL parameter, not a privileged secret, GitHub token, or session) and changing one path parameter; the scoping bypass is a straightforward code-level oversight (`stack` method override) rather than a complex chained attack, making it likely to be found and exploited by anyone who has legitimately received one CCMenu URL.

### Recommendation
- In `Shipit::CCMenuUrlController#fetch`, create the `ApiClient` scoped to the specific stack (`stack: stack`) instead of leaving `stack_id` nil.
- In `Shipit::Api::CCMenuController`, remove the `stack` override and use the inherited `BaseController#stack`/`stacks` helpers so lookups are constrained to `current_api_client.stack_id` when the token is stack-scoped.
- Add a regression test asserting that a CCMenu token issued for stack A returns 404/403 when used against stack B's CCMenu endpoint.

### Proof of Concept
1. As a legitimate user, visit stack A's settings page, which triggers `CCMenuUrlController#fetch` and returns a URL like `.../api/stacks/A/ccmenu.xml?token=<TOKEN>`.
2. Obtain `<TOKEN>` (e.g., from a publicly displayed CI badge/dashboard pointing at stack A).
3. Send `GET /api/stacks/B/ccmenu.xml?token=<TOKEN>` for an unrelated stack B.
4. `CCMenuController#authenticate_api_client` authenticates `<TOKEN>` successfully (permission `read:stack` present), and `CCMenuController#stack` resolves `Stack.from_param!("B")` directly, returning stack B's deploy/rollback status — despite the token never having been authorized for stack B.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-22)
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
