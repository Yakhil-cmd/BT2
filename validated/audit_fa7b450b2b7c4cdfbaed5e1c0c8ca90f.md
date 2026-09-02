### Title
Stack-scoped API tokens can read the CI status of any stack via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the stack-resolution logic used everywhere else in the API to enforce token scoping, and in doing so drops the scoping check entirely. A `read:stack` token that was created scoped to a single stack (`ApiClient#stack_id`) can be used to read the build/deploy status of any stack in the installation, not just the one it was issued for.

### Finding Description
`Api::BaseController` defines the canonical, scope-respecting stack lookup: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped (`stack_id?` true), and `stack` resolves `params[:stack_id]` only within that restricted set. Every other API controller inherits this and is therefore correctly bound: the stack the token *authorizes* access to equals the stack it *touches*.

`Api::CCMenuController`, however, redefines `stack` to bypass the scoped `stacks` relation entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, instead of `stacks.from_param!(params[:stack_id])`. The controller still declares `require_permission :read, :stack`, which only checks that the token *has* the `read:stack` permission string via `ApiClient#check_permissions!`: [3](#0-2) 

`check_permissions!` never consults `stack_id`; permission checking and stack-scope checking are two separate mechanisms, and only `BaseController#stack`/`#stacks` enforces the latter. Because `CCMenuController#stack` skips that method, the binding "stack a token authorizes == stack the token can read" is broken.

Additionally, `CCMenuController` overrides `authenticate_api_client` to also accept the token via `params[:token]` (not just the `Authorization` header), which is how the token is meant to be shared (see `CCMenuUrlController`, which mints a `read:stack`-only, stack-scoped `ApiClient` and hands back a URL containing `?token=...`): [4](#0-3) 

This URL is designed to be pasted into third-party CI dashboard tools (CCMenu clients), i.e. it is expected to leave the trust boundary of the logged-in Shipit session. The whole point of scoping the token to one stack is to limit what an untrusted holder of that URL/token can see. The controller's own scope bypass defeats that design goal.

### Impact Explanation
An attacker who obtains a legitimately-issued, single-stack-scoped `read:stack` CCMenu token (e.g. one pasted into a third-party CI status widget, shared in a public dashboard, or leaked via a request log/referrer) can use that same token/URL pattern against `GET /api/stacks/:stack_id/ccmenu.xml?token=...` for **any** `stack_id` in the Shipit installation, retrieving that other stack's latest deploy/rollback status (`stack.deploys_and_rollbacks.last`), including build/lock status. This is an unauthenticated-relative-to-scope read of stack state belonging to repositories the token holder was never granted access to — matching the "High: unauthenticated read of stack state... " impact class, because the token's authorization is for one stack only, yet the endpoint lets it touch every stack.

### Likelihood Explanation
Likelihood is significant: CCMenu tokens are specifically generated to be embedded in a shareable URL (`CCMenuUrlController`) for use by third-party, non-Shipit-authenticated tooling, which is the intended low-trust distribution path for this credential. No additional secret, session, or GitHub credential is required — only the token that the feature itself is designed to hand out externally, plus knowledge/guessing of another stack's `to_param` (a predictable `owner/repo/environment`-style identifier, not a secret).

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation from `BaseController`, i.e. `stacks.from_param!(params[:stack_id])`, instead of calling `Stack.from_param!` directly, so a stack-scoped token cannot resolve stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. An admin uses `CCMenuUrlController#fetch` (or equivalent) on `stack_a`, minting/reusing an `ApiClient` with `permissions: ['read:stack']` and `stack_id: stack_a.id`, and receives a URL such as `/api/stacks/stack_a/ccmenu.xml?token=<TOKEN>`.
2. This URL is pasted into a public/third-party CI dashboard, so `<TOKEN>` becomes exposed outside the Shipit session boundary — exactly the scenario `stack_id` scoping is meant to contain.
3. An unprivileged party who obtains `<TOKEN>` (from the dashboard config, a proxy log, etc.) requests `/api/stacks/stack_b/ccmenu.xml?token=<TOKEN>` for an arbitrary other stack `stack_b`.
4. `authenticate_api_client` in `CCMenuController` accepts the token via `params[:token]` and sets `@current_api_client` to the `stack_a`-scoped client.
5. `require_permission :read, :stack` passes because the client's `permissions` array contains `read:stack` (scope is never checked here).
6. `stack` resolves via `Stack.from_param!(params[:stack_id])`, unscoped, and returns `stack_b`.
7. The response renders `stack_b`'s latest deploy/rollback status, which the token was never authorized to access.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
