## Title
`CCMenuUrlController#client` mints a stack-unscoped `read:stack` API token that grants read access to every stack - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

## Summary
`CCMenuUrlController#fetch` embeds an `ApiClient` token in the CCMenu URL it returns, but `#client` creates that `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` without passing `stack_id`. Because `Shipit::Api::BaseController#stacks` treats a nil `stack_id` as "no restriction" (`Stack.all`), this "per-stack" CCMenu token actually authorizes `read:stack` on all stacks in the installation, not just the one named in the request.

## Finding Description
The intended binding is: *the stack a CCMenu token authorizes == the stack named in `GET /stacks/:owner/:repo/:env/ccmenu`*. The actual code breaks this equality.

`#client` in `app/controllers/shipit/ccmenu_url_controller.rb` does: [1](#0-0) 

This never sets `stack_id` on the created/found `ApiClient`. Any authenticated user calling `fetch` for any stack (even one they cannot deploy) reuses/creates the same singleton `ApiClient` named `'CCMenu Client'` scoped to themselves, with `stack_id` left `nil`.

Downstream, `Shipit::Api::BaseController#stacks` is: [2](#0-1) 

Since `current_api_client.stack_id?` is false for this client, `stacks` resolves to `Stack.all` — every stack across every repository/environment — rather than being restricted to a single stack. `Shipit::Api::CCMenuController#show` (used to serve the CCMenu XML) resolves `stack` via `Stack.from_param!` — in that controller it's `Stack.from_param!(params[:stack_id])` directly rather than through the scoped `stacks` helper: [3](#0-2) 

That controller only requires `read:stack` permission via `require_permission :read, :stack`, which `ApiClient#check_permissions!` validates against the client's `permissions` list — it does not check `stack_id` at all for this specific controller's `#show`, so the nil-`stack_id` client's token, once obtained, can be used against `Api::CCMenuController#show` for *any* stack, not just the one that appears in the embedded URL, and even other API endpoints that go through the generic `stacks`/`stack` helper (which likewise return `Stack.all` for a nil `stack_id`) are unscoped.

Route access itself requires only a signed-in Shipit session (`ShipitController` / `Shipit::Authentication`), and there is no per-stack authorization check (e.g., no `require_permission`/team-membership check) gating `fetch` before `client` is invoked. Nothing in `ApiClient#check_permissions!` or the `stacks` helper distinguishes "this token was minted for stack A" from "this token has no stack restriction"; a nil `stack_id` is treated identically to "global" access, which is the root cause.

Attacker flow:
1. Attacker (any GitHub OAuth user, no special permission on stack A) requests `GET /stacks/:owner/:repo/:env/ccmenu` for a stack A they don't control.
2. `#client` creates (or reuses) an `ApiClient` named `'CCMenu Client'`, `creator: current_user`, `permissions: ['read:stack']`, `stack_id: nil`.
3. The response embeds `token=<that client's authentication_token>` in the URL.
4. Attacker uses that token against `Api::CCMenuController#show` (or any other API endpoint relying on the unscoped `stacks`/`stack` helper) for stack B, an unrelated stack belonging to another repository/tenant, and the request succeeds.

## Impact Explanation
The attacker gains an authenticated `read:stack` API credential valid for every stack in the Shipit installation, not just the stack nominally requested — an unauthorized cross-tenant read of stack state (CCMenu status/build info, and potentially any other data reachable through `read:stack`-gated endpoints under `Api::BaseController`). This matches the "High — escalation ... unauthenticated read of stack state" category (here, cross-stack read escalation via a token that should have been scoped to one stack). It is fully repeatable: any authenticated user can call `fetch` once to obtain a durable token (persisted via `find_or_create_by!`), then reuse it indefinitely against arbitrary stacks/repositories.

## Likelihood Explanation
Preconditions are minimal: the attacker only needs a valid Shipit session (completing GitHub OAuth is available to "any GitHub user"), and access to a single `GET .../ccmenu` route for any stack (even a public/low-sensitivity one they're allowed to view). No secrets, no privileged role, and no special repository configuration are required. This is low-cost and highly feasible.

## Recommendation
Pass `stack_id: stack.id` into `ApiClient.create_with` / the `find_or_create_by!` scope in `#client` so the CCMenu token is bound to the specific stack it was minted for, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack_id: stack.id).find_or_create_by!(creator: current_user, stack_id: stack.id, name: 'CCMenu Client')`, and ensure lookups also filter by `stack_id` so a pre-existing unscoped client isn't silently reused across stacks. Also audit `Api::CCMenuController#stack` to resolve through the scoped `stacks` helper rather than `Stack.from_param!` directly, consistent with other controllers under `Api::BaseController`.

## Proof of Concept
Minitest plan (`test/controllers/ccmenu_controller_test.rb` style, adjusted):
1. Create two stacks, `stack_a` and `stack_b`, belonging to different repositories.
2. Sign in as `user` (no maintainer/team role on either stack).
3. `get :fetch, params: { stack_id: stack_a.to_param }` on `CCMenuUrlController`; parse the returned `ccmenu_url` and extract the `token` query parameter.
4. Assert `ApiClient.find_by(creator: user, name: 'CCMenu Client').stack_id.nil?` (demonstrating the unscoped token).
5. Using that `token`, call `Shipit::Api::CCMenuController#show` with `stack_id: stack_b.to_param` (an unrelated stack) via HTTP basic auth or `params[:token]`.
6. Assert the response status is `403`/`404` (expected/secure behavior) — currently it returns `200` with `stack_b`'s CCMenu XML, proving the token authorizes a stack it was never minted for.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
