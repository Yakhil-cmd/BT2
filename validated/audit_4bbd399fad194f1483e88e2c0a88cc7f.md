### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the shared `stack` helper and resolves the target stack directly from `params[:stack_id]` via `Stack.from_param!`, completely bypassing the `ApiClient` stack-scoping logic used by every other API controller. This breaks the binding: *the stack a token is authorized for* == *the stack the endpoint actually operates on*.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-aware accessor: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is scoped to a single stack (`current_api_client.stack_id?`), and only falls back to `Stack.all` for unscoped clients. Every other API controller (`Api::StacksController`, etc.) relies on this scoped `stack`/`stacks` method, so a client created with `stack_id` set (e.g. via `CCMenuUrlController#client`, which builds an `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)`) can only read data about the one stack it's bound to.

`Api::CCMenuController` re-defines `stack` to skip that scoping entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

This calls `Stack.from_param!` on the unrestricted `Stack` relation instead of the scoped `stacks` relation, so `current_api_client.stack_id` is never consulted. `require_permission :read, :stack` only checks that the token has the `read:stack` permission bit — it never verifies which stack the permission was granted for [3](#0-2) .

Because `CCMenuUrlController#client` mints exactly this kind of stack-scoped, `read:stack`-only token and hands its URL/token out (e.g. embedded in a CCMenu/CI dashboard URL) for a specific stack [4](#0-3) , the resulting token is expected to only ever reveal information about that one stack. `CCMenuController#authenticate_api_client` additionally accepts the token as a plain query-string parameter, `params[:token]`, rather than requiring the `Authorization` header [5](#0-4) , making the token easy to observe/replay (URLs are commonly logged, cached, shared).

This is the direct analog of the `Dispenser.retain()` bug: a caller with a narrow, legitimately-issued authorization (claim for `retainer` target / read `stack A`) is not restricted from directing the call at an unintended target (any stack / stack B), because the authorization check validates only the *operation* and not the *scope-binding* between the caller's token and the specific resource acted upon.

### Impact Explanation
Any holder of a stack-scoped CCMenu token (issued for stack A with only `read:stack` permission) can query `GET /api/:owner/:repo/:stack/ccmenu.xml?token=...` (or any `stack_id`) for a completely different stack B and receive that stack's name, current activity, last build status/label, timestamps, and web URL — data the token was never authorized to see. This is an authorization-scope escalation: read access to arbitrary stack state via a token that should be confined to a single stack, matching the "escalation into authorization... unauthenticated read of stack state" High-impact category.

### Likelihood Explanation
Any legitimate, unprivileged consumer of a CCMenu URL (a common integration point, deliberately designed to be embedded in dashboards/CI tools and passed via a bare query-string token) can trivially enumerate other `stack_id` values (stack identifiers are not secret — they are owner/repo/branch names visible throughout the UI) and swap them into the same URL. No special tooling, session, or elevated credential beyond the token they already legitimately possess is required.

### Recommendation
Have `Api::CCMenuController#stack` reuse the scoped `stacks` method from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that `current_api_client.stack_id` scoping is enforced consistently with all other API endpoints.

### Proof of Concept
1. An operator calls `CCMenuUrlController#fetch` for `stack_id=owner/repoA/main`, receiving a token whose underlying `ApiClient` has `stack_id = <id of repoA stack>` and `permissions = ["read:stack"]` [4](#0-3) .
2. This token/URL is shared or embedded in a dashboard (its intended use).
3. An attacker holding that URL swaps the `stack_id` in the path to a different, unrelated stack B (`owner/repoB/main`) they should have no visibility into, keeping the same `token` query parameter.
4. `CCMenuController#authenticate_api_client` accepts the token (valid signature, valid `ApiClient`), and `require_permission :read, :stack` passes because the client has `read:stack` permission generally [5](#0-4) .
5. `CCMenuController#stack` resolves stack B directly via `Stack.from_param!(params[:stack_id])`, ignoring that the client's `stack_id` is scoped to stack A [6](#0-5) .
6. The response renders stack B's deploy/build status XML, disclosing data the token was never authorized to access.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
