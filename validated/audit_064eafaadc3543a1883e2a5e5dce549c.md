This confirms the vulnerability. `Shipit::Api::CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) overrides `Shipit::Api::BaseController#stack` (`app/controllers/shipit/api/base_controller.rb:78-80`), bypassing the `stacks` scoping method that restricts a stack-scoped `ApiClient` to `Stack.where(id: current_api_client.stack_id)` (`app/controllers/shipit/api/base_controller.rb:74-76`). `require_permission :read, :stack` only checks the client's permission string, not which specific stack it's scoped to (`app/controllers/shipit/api/base_controller.rb:82-84`, `app/models/shipit/api_client.rb:38-45`).

### Title
Stack-scoped ApiClient tokens can read CCMenu status of any stack, not just the authorized one - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` records can be scoped to a single `stack_id` (e.g. via `CCMenuUrlController#client`, `app/controllers/shipit/ccmenu_url_controller.rb:15-18`, which creates a client with `permissions: %w[read:stack]` bound to one stack). The intended binding is: `ApiClient#stack_id` authorizes read access only to that one `Stack`. `CCMenuController#stack` breaks this binding by resolving the target stack directly from the request parameter instead of from the scoped `stacks` collection.

### Finding Description
`BaseController#stacks` enforces the scoping: if the authenticated `ApiClient` has a `stack_id`, only that stack is in scope; otherwise all stacks are in scope (`app/controllers/shipit/api/base_controller.rb:74-76`). `BaseController#stack` correctly derives the target stack from that scoped collection: `stacks.from_param!(params[:stack_id])` (`app/controllers/shipit/api/base_controller.rb:78-80`).

`CCMenuController`, however, defines its own private `stack` method that ignores `stacks` entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [1](#0-0) 

`require_permission :read, :stack` (declared at the controller class level) only calls `current_api_client.check_permissions!(:read, :stack)`, which merely checks that `"read:stack"` is present in the client's `permissions` array — it performs no per-stack authorization check [2](#0-1) . There is no code path in `CCMenuController#show` that re-applies the `stack_id` scoping that `BaseController#stack` provides.

As a result, any `ApiClient` token with the generic `read:stack` permission — even one deliberately created and scoped to a single stack (as done by `CCMenuUrlController#client`, which mints such tokens for the public, unauthenticated CCMenu XML feed) — can be replayed against `GET /api/stacks/:stack_id/ccmenu.xml` with an arbitrary `stack_id` belonging to any other stack, and will successfully render that other stack's deploy/build status.

### Impact Explanation
This crosses the "stack a token authorizes vs. stack it touches" trust boundary called out in scope: a token intentionally minted and distributed (e.g. embedded in a CCMenu client URL, which is designed to be handed out with `BasicAuth` skipped and the token placed directly in the query string, `app/controllers/shipit/ccmenu_url_controller.rb:8-11`) leaks build/deploy status (name, activity, last build status/label/time, web URL) of every stack in the Shipit instance, not just the one it was scoped and issued for. This is an unauthenticated read of stack state beyond what the credential holder was authorized to see, matching the in-scope "unauthenticated read of stack state, task streams or deploy output" High-impact category, since the CCMenu token itself is designed to be used without further authentication and its scope is meant to be a single stack.

### Likelihood Explanation
Likelihood is high: exploitation requires only possession of any single valid `read:stack`-scoped CCMenu token (which is, by design, distributed outside of any authenticated session, e.g. pasted into third-party CI dashboard tools) and changing the `stack_id` route parameter to another stack's slug — no other credential or write access is needed.

### Recommendation
Remove the custom `stack` override in `CCMenuController`, or reimplement it to reuse the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) so that stack-scoped tokens cannot escape their assigned stack.

### Proof of Concept
1. Admin creates a CCMenu URL for `stack-a` via the UI; this creates (or reuses) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to `stack-a`'s id (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`), and returns a URL such as `https://shipit.example.com/api/stacks/org/repo-a/production/ccmenu.xml?token=<token>`.
2. An attacker who obtains this `token` (e.g. from a public CI dashboard config, a leaked URL, or a compromised third-party integration) sends:
   `GET /api/stacks/org/repo-b/production/ccmenu.xml?token=<token>`
   where `org/repo-b/production` is a completely different, unrelated stack.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully via `ApiClient.authenticate(params[:token])` (`app/controllers/shipit/api/ccmenu_controller.rb:33-36`).
4. `require_permission :read, :stack` passes because the client's `permissions` includes `"read:stack"`, regardless of its `stack_id` (`app/models/shipit/api_client.rb:38-45`).
5. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly against `repo-b/production`, bypassing the `stack_id` scoping that `BaseController#stack`/`#stacks` would have enforced (`app/controllers/shipit/api/ccmenu_controller.rb:29-31` vs `app/controllers/shipit/api/base_controller.rb:74-80`).
6. The response renders `repo-b/production`'s deploy status XML, disclosing information about a stack the token was never authorized to access.

### Citations

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
