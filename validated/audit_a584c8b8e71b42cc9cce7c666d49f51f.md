### Title
CCMenu API token minted with no `stack_id` grants read access to every stack, not just the caller's own - ([File: app/controllers/shipit/ccmenu_url_controller.rb], [File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuUrlController#fetch` mints a `read:stack` `ApiClient` token without setting `stack_id`, then embeds it in a URL that looks scoped to one stack path. `Api::CCMenuController` overrides the base `stack` lookup to bypass the `stacks` scoping method that would otherwise restrict lookups by `current_api_client.stack_id`, so the token authenticates reads against any stack.

### Finding Description
The broken binding: the intended equality is `token.readable_stacks == {stack named in the CCMenu URL path}`, but the actual behavior is `token.readable_stacks == Stack.all`.

In `app/controllers/shipit/ccmenu_url_controller.rb:7-18`, `fetch` builds a URL for `api_stack_ccmenu_url(stack_id: stack.to_param)` and appends a token from: [1](#0-0) 
`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — note `stack_id` is never passed, so the created/found `ApiClient` row has `stack_id: nil`.

`Api::BaseController` defines a `stacks`/`stack` scoping mechanism intended to enforce per-client stack restriction: [2](#0-1) 
`stacks` returns `Stack.where(id: current_api_client.stack_id)` only if `current_api_client.stack_id?` is true; otherwise it returns `Stack.all`. Since the CCMenu client's `stack_id` is nil, `stacks` degrades to `Stack.all` even for clients that were conceptually meant to be scoped.

Worse, `Api::CCMenuController` doesn't even use the base `stacks`/`stack` scoping — it defines its own `stack` method that ignores `current_api_client` entirely: [3](#0-2) 
`@stack ||= Stack.from_param!(params[:stack_id])`. The only guard is `require_permission :read, :stack`, which just checks that `"read:stack"` is in the token's `permissions` array — it is not stack-specific: [4](#0-3) 

So any token minted by `CCMenuUrlController` — regardless of which stack the user requested it for — authenticates against `Api::CCMenuController#show` for **any** `stack_id` in the path, since that controller performs no scope check against `current_api_client.stack_id` at all.

Exploit flow: a user with UI access to stack A visits `/stacks/:owner/:repo/:env/cc_menu_url` (reachable via `current_user`/session, not an API client), receives `{ ccmenu_url: ".../api/stacks/A/.../cc_menu_url.xml?token=..." }`, extracts `token`, and replays it against `/api/stacks/B/.../cc_menu_url.xml?token=...` for stack B they have no access to. The request succeeds because `ApiClient.authenticate(token)` only verifies the signature/id, `check_permissions!` only checks the generic `read:stack` permission, and `stack` in `CCMenuController` performs an unscoped `Stack.from_param!` lookup.

### Impact Explanation
The attacker obtains unauthenticated (relative to the target stack) read access to deploy/task state (`latest_deploy` info rendered in the CCMenu XML) for any stack on the Shipit instance, not just the stack they were authorized to view in the UI. This matches the "High - unauthenticated read of stack state" category. It's repeatable indefinitely against any `stack_id`, and the token is not scoped by time or single-use, so the blast radius spans every stack/tenant in the deployment, not just the requester's.

### Likelihood Explanation
Preconditions are minimal: any logged-in user (via whatever OAuth/session mechanism the host configures, per the README broad org login) with UI access to at least one stack can trigger `CCMenuUrlController#fetch` for that stack and receive a token. No special permission, secret, or privileged role is required beyond an ordinary Shipit login. The attack cost is one authenticated request plus arbitrary unauthenticated replay requests against `Api::CCMenuController` for other stack IDs, all doable purely via HTTP without any GitHub secrets.

### Recommendation
Set `stack_id: stack.id` when creating the `ApiClient` in `CCMenuUrlController#client`, and make `Api::CCMenuController#stack` (and ideally the base `stack`/`stacks` helpers universally) always scope lookups through `current_api_client.stack_id` rather than allowing an unscoped `Stack.from_param!` bypass, so a nil `stack_id` never implicitly means "all stacks" for tokens that were intended to be single-stack-scoped.

### Proof of Concept
Minitest plan (no live GitHub required):
1. Create `stack_a` and `stack_b` (`Shipit::Stack`) with a user who has UI read access to `stack_a` only (or simply any authenticated user, since Shipit's UI authorization for `cc_menu_url` isn't stack-restrictive beyond `current_user` presence).
2. `sign_in user`; `get cc_menu_url_stack_path(stack_a)` (or equivalent named route for `ccmenu_url#fetch`); parse the JSON body, extract `ccmenu_url`, and parse out the `token` query param.
3. Assert: `ApiClient.last.stack_id.nil?` (documenting the divergence: token bound conceptually to `stack_a` but `stack_id` is nil).
4. `get "/api/stacks/#{stack_b.to_param}/cc_menu.xml", params: { token: token }` (path per `Api::CCMenuController`'s route for `stack_b`, a stack the user was never granted).
5. Assert `response.status == 200` and the XML body reflects `stack_b`'s deploy state — proving the token minted for `stack_a` reads `stack_b`.
6. Contrast: assert that if `stack_id` were correctly set on the `ApiClient`, the same request to `stack_b` would 404/403 (this is the intended equality that the current code breaks).

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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
