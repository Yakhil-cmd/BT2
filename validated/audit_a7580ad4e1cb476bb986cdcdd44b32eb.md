### Title
CCMenu API tokens are never scoped to a stack, allowing cross-stack read access to any stack via `Api::CCMenuController#show` - (File: app/controllers/shipit/ccmenu_url_controller.rb, app/controllers/shipit/api/ccmenu_controller.rb, app/models/shipit/api_client.rb)

### Summary
`CCMenuUrlController#client` creates an `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, but never sets `stack_id` on that client — so every CCMenu client's `stack_id` is always `nil`. On top of that, `Api::CCMenuController` defines its own `stack` method that resolves `Stack.from_param!(params[:stack_id])` directly against `Stack` instead of the stack-restricted `stacks` scope used elsewhere in `Api::BaseController`. The combination means a `read:stack` CCMenu token minted for one stack can read the CCMenu status (`/api/1/stacks/:stack_id/ccmenu`) of any stack in the Shipit instance.

### Finding Description
The binding that should hold is: for a token `t` returned by `#fetch` for stack `S`, `ApiClient.authenticate(t).stack_id == S.id`, and `Api::CCMenuController#show` must only serve stacks where `stack.id == current_api_client.stack_id` (when `stack_id` is present).

Tracing the code:
- `CCMenuUrlController#client` [1](#0-0)  only passes `permissions: %w[read:stack]` to `create_with`; `stack_id` is never assigned to the created/found `ApiClient`. `ApiClient` itself declares `belongs_to :stack, optional: true` [2](#0-1) , so a client with `stack_id == nil` is a perfectly valid, unscoped record.
- `Api::BaseController#stacks`, used by most API controllers, restricts the visible stacks when `current_api_client.stack_id?` is true: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [3](#0-2) . Since CCMenu clients always have `stack_id == nil`, this scoping is a no-op even where it is used.
- `Api::CCMenuController` doesn't even rely on that scope: it defines its own `stack` private method that calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, bypassing `current_api_client.stack_id` entirely [4](#0-3) .
- `require_permission :read, :stack` only calls `current_api_client.check_permissions!('read', 'stack')` [5](#0-4) , `app/controllers/shipit/api/base_controller.rb" start="82" end="84" />, which merely checks the `permissions` array contains `read:stack` — it performs no per-stack authorization check at all [6](#0-5) .

Attacker flow: an authenticated low-privilege Shipit user (any GitHub OAuth login, no team membership required for `#fetch` since `CCMenuUrlController` only requires a session, not `Shipit.github_teams` membership) calls `GET /ccmenu/:any_stack_id` once for any stack they can name. This mints/returns a `read:stack` `ApiClient` token with `stack_id = nil`. They then call `GET /api/1/stacks/:other_stack_id/ccmenu?token=...` for any other stack in the instance — including stacks belonging to repositories/teams the attacker has no access to — and `Api::CCMenuController#show` happily resolves and renders that stack's latest deploy/rollback state.

This differs from the question's framing (which suspected `find_or_create_by!` returning a *stale* stack_id from a prior call) — the actual root cause is broader: `stack_id` is **never** populated on the client at all, on the *first* call too, so the divergence exists immediately, not just on a second `#fetch`. None of the listed guards (`require_permission!`, the `stacks` scope, model validations) prevent this because `Api::CCMenuController` doesn't use the `stacks` scope, and `check_permissions!` has no stack-awareness.

### Impact Explanation
Any authenticated Shipit user can read CCMenu status (latest deploy/rollback id, end time, running state) for **any stack in the Shipit installation**, regardless of GitHub team membership or repository access, using a token they legitimately minted for an unrelated stack. This is an unauthenticated-relative-to-target-stack read of stack state, matching the "High" impact category (escalation/read of stack state outside `Shipit.github_teams` authorization). It is fully repeatable against arbitrary stacks — the attacker simply changes `:stack_id` in the URL param; no new token is even required since the same token works for every stack.

### Likelihood Explanation
Preconditions are minimal: only a normal authenticated Shipit session (standard OAuth login) is required to reach `CCMenuUrlController#fetch`; the code shows no team/permission check gating access to `#fetch` for a given `stack_id` beyond `Stack.from_param!` finding the record. No secrets, no special role, and no repeated interaction with `find_or_create_by!` races are needed — the vulnerability is present on the very first call. Attacker cost is a single HTTP request plus reuse of the returned token against other stack IDs, which are typically guessable/enumerable slugs. This makes the issue highly likely to be exploitable wherever this engine is deployed with `Shipit.github_teams` restricting some stacks.

### Recommendation
Set `stack_id: stack.id` in the `create_with`/`find_or_create_by!` call in `CCMenuUrlController#client`, scope the `find_or_create_by!` lookup to include `stack_id` (or create a fresh client per stack), and make `Api::CCMenuController#stack` use the shared `stacks` scope (`stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so that a client's `stack_id` is enforced consistently across all API controllers.

### Proof of Concept
minitest plan (`test/controllers/ccmenu_controller_test.rb` and `test/controllers/api/ccmenu_controller_test.rb`):
1. Create two stacks `stack_a` and `stack_b` (different repositories/teams).
2. As `walrus` user, `GET :fetch, params: { stack_id: stack_a.to_param }` via `CCMenuUrlControllerTest`; extract `token` from the returned `ccmenu_url`.
3. Assert `ApiClient.find_by(creator: walrus, name: 'CCMenu Client').stack_id.nil?` (documents the root cause — never bound to any stack).
4. In an `Api::CCMenuControllerTest`, perform `get :show, params: { stack_id: stack_b.to_param, token: token }` using the token minted for `stack_a`.
5. Assert `response.status == 200` and that the rendered XML corresponds to `stack_b`'s latest deploy — proving the token scoped nominally to `stack_a` authenticates reads against `stack_b`, violating `current_api_client.stack_id == stack_named_in_request.id`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L7-10)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
