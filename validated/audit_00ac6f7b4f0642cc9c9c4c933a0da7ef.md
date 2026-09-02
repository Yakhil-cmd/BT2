### Title
CCMenu API endpoint bypasses per-stack ApiClient scoping, allowing a stack-scoped token to read any stack's deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The external report's root cause is a verification asymmetry: one code path checks a narrow set of fields (L2 target + selector) while the actual operation acts on a broader, unverified set of fields (refund addresses, `value`), breaking the invariant that "what is verified" == "what is executed." The same class of asymmetry exists in `shipit-engine`'s `Api::CCMenuController`, where the stack-scoping enforced for every other API endpoint is silently dropped.

### Finding Description
`Api::BaseController` establishes the authorization invariant that an `ApiClient` may only touch the stack(s) it was scoped to: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client has one, and `stack` resolves the requested `params[:stack_id]` against that restricted relation. Every other controller in `app/controllers/shipit/api/**` relies on this `stack`/`stacks` helper (e.g. `Api::StacksController#stack` at `app/controllers/shipit/api/stacks_controller.rb:87-89` uses `stacks.from_param!(params[:id])`), so the binding `stack the token authorizes == stack the action touches` holds everywhere else.

`Api::CCMenuController` however overrides `#stack` and bypasses the scoped relation entirely: [2](#0-1) 

Instead of `stacks.from_param!(params[:stack_id])`, it calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model. The `require_permission :read, :stack` before-action only checks that the authenticated `ApiClient` has the generic `read:stack` permission string on its `permissions` array — it never re-checks `current_api_client.stack_id` against the resolved `stack`. The controller also swaps in a token-based (`params[:token]`) authentication path rather than the header-based Basic auth used elsewhere, but that path still produces an `ApiClient` whose optional `stack_id` (see `belongs_to :stack, optional: true` in `app/models/shipit/api_client.rb:8`) is meant to constrain it.

Before the equality invariant breaks: `stack == Stack.where(id: current_api_client.stack_id) ∩ {params[:stack_id]}` (i.e., only reachable if the requested id matches the token's own scope, or the token has no scope at all).
After: `stack == Stack.find_by(param: params[:stack_id])` with **no** dependency on `current_api_client.stack_id` at all — any stack id can be supplied regardless of what stack the token was actually granted access to.

### Impact Explanation
Any holder of a valid CCMenu (or any other) `read:stack`-scoped `ApiClient` token that is restricted to a specific stack (`api_client.stack_id` set) can pass an arbitrary `stack_id` to `Api::CCMenuController#show` and receive that other stack's deploy/rollback status (latest deploy id, end time, running state) via the rendered `shipit/ccmenu/project` XML view. This is an unauthorized cross-stack read of stack/deploy state — the token's authorization boundary (one stack) is bypassed to read another stack it was never granted. This matches the "High - ... unauthenticated read of stack state, task streams or deploy output" category, since the CCMenu action requires no additional verification of the caller's actual entitlement to the target stack beyond a generic, non-stack-specific permission string.

### Likelihood Explanation
Exploitation only requires possession of any valid `read:stack` API token (e.g., a legitimately-issued, stack-scoped CCMenu URL/token for stack A) and knowledge or guessing of another stack's `to_param` (slug/id, which are not secret and are visible throughout the UI/API). No repository write access, GitHub credentials, or privileged account is needed — only an unprivileged holder of a narrowly-scoped token. This is a straightforward, deterministic code path (no timing/race conditions), making exploitation highly likely once a scoped token is available.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited scoped resolution instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that it goes through `Api::BaseController#stacks`, which enforces `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`. This restores the invariant that the stack touched by the action is always a subset of the stack(s) the token was authorized for.

### Proof of Concept
1. As an authorized user, generate a CCMenu URL/token for Stack A (`Api::CCMenuController` route, `params[:token]` from `CCMenuUrlController`) or otherwise obtain an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A's id.
2. Send `GET /api/1/stacks/:stack_id/ccmenu.xml?token=<tokenForStackA>` but substitute `:stack_id` with Stack B's `to_param` (a different, unrelated stack the token was never scoped to).
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unconditionally, `before_action :authenticate_api_client` and `require_permission :read, :stack` both pass (the token has `read:stack`), and the controller renders Stack B's latest deploy/rollback status and running state — data the token holder was never authorized to access.

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
