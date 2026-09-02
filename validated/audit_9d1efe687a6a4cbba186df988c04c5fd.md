### Title
Api::CCMenuController#stack bypasses per-token stack scoping, allowing a stack-scoped CCMenu token to read any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
This is the same bug class as the C4 finding: a check is performed against one piece of state (the `ApiClient`'s permission/scope) while the actual operation is carried out against a different, unchecked piece of state (`params[:stack_id]`). In `HomeFi`, `lenderFee` was validated at write-time but not at use-time, breaking `lenderFee ∈ [0, 1000)`. In `shipit-engine`, `ApiClient#stack_id` is meant to bind a token to exactly one stack, but `Api::CCMenuController` resolves the stack to act on without applying that binding, breaking the invariant `stack_acted_on == stack_authorized_for`.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting resolution of "which stack can this API client touch": [1](#0-0) 

`stacks` is restricted to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id` set, and `stack` is derived from that restricted relation via `from_param!`. This is the binding: `ApiClient#stack_id` (what a token authorizes) must equal the stack a request actually touches.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoped relation entirely and resolve directly against the global `Stack` model: [2](#0-1) 

`stack` here is `Stack.from_param!(params[:stack_id])` — i.e., any stack in the installation, regardless of `current_api_client.stack_id`. The controller still calls `require_permission :read, :stack`, but that check only verifies the client's `permissions` array contains `read:stack`; it never verifies that the target stack equals `current_api_client.stack_id`.

CCMenu tokens are specifically designed to be stack-scoped, minimal-privilege, "read only" tokens meant for external CI dashboard tools such as CCMenu. They are created and handed out per-stack: [3](#0-2) 

The generated URL includes `stack_id: stack.to_param` in the path plus a `token` for a `read:stack`-permissioned `ApiClient`. Because `ApiClient` is a `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` record without a `stack_id` set on it (only `permissions: %w[read:stack]` is passed to `create_with`), the token itself is not scoped to a specific stack at the model level — but even in the general (non-CCMenu) API case where an `ApiClient.stack_id` is explicitly set to lock a token to one stack (used elsewhere in `Api::BaseController#stacks`, and exercised by the test `"an api client scoped to a stack will only see that one stack"` in `test/controllers/api/stacks_controller_test.rb`), `CCMenuController` silently ignores that scoping and lets the token read the `deploys_and_rollbacks` of *any* stack by just supplying a different `stack_id` in the request path, since `Stack.from_param!` is unscoped.

### Impact Explanation
Any bearer of a `read:stack`-permissioned API token — including a token deliberately scoped to a single stack via `ApiClient#stack_id` (the exact security mechanism `Api::BaseController#stacks` exists to enforce) — can query `GET /api/1/stacks/:stack_id/ccmenu.xml` for an arbitrary `stack_id` and obtain that other stack's latest deploy/rollback status (id, `ended_at`, `running?` and the rendered CCMenu XML detail). This is an unauthorized read of stack state across the authorization boundary the `ApiClient.stack_id` scoping is designed to enforce — matching the "High: unauthenticated/unauthorized read of stack state" impact category, since it discloses task/deploy state for stacks the token holder was never granted access to.

### Likelihood Explanation
Any unprivileged holder of a stack-scoped, read-only API token (the exact kind of low-trust credential the CCMenu flow purposely issues to external dashboard integrations) can trigger this by simply changing the `stack_id` in the URL — no privileged account, session, or secret beyond the token they already legitimately hold is required. The bypass is a single method override (`stack`) that is trivial to reach on every request to this controller.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped resolution from `Api::BaseController`, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so that `current_api_client.stack_id` (when present) is always enforced, consistent with every other `Api::BaseController` subclass, instead of resolving against the unscoped `Stack` model.

### Proof of Concept
1. Have Shipit issue a stack-scoped, read-only CCMenu-style token, or otherwise obtain an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to stack A (e.g., via `test/fixtures/shipit/api_clients.yml`'s `here_come_the_walrus` fixture, which is scoped to stack `shipit`, analogous to `test/controllers/api/stacks_controller_test.rb`'s `"an api client scoped to a stack will only see that one stack"` test).
2. Send `GET /api/1/stacks/<stack_B_id>/ccmenu.xml?token=<token-for-stack-A>` where stack B is a different stack the client was never authorized for.
3. `authenticate_api_client` succeeds (valid token), `require_permission :read, :stack` passes (`permissions` includes `read:stack`), and `stack` resolves via `Stack.from_param!(params[:stack_id])` to stack B regardless of the token's `stack_id`.
4. The response renders `shipit/ccmenu/project` with stack B's actual `deploys_and_rollbacks`, leaking build/deploy status for a stack outside the token's authorized scope — contrast with `Api::StacksController#index`, which correctly returns only the authorized stack for the same token (as asserted in `test/controllers/api/stacks_controller_test.rb:217-223`).

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
