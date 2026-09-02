### Title
CCMenu token is not scoped to any stack, so a leaked CCMenu URL grants read access to every stack via `Api::CCMenuController#show` - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` with `read:stack` permission but never sets `stack:` on it, and `Api::CCMenuController#stack` bypasses the base class's stack-scoping (`stacks`) entirely by calling `Stack.from_param!` directly. As a result the token embedded in a CCMenu URL is valid for reading CI status of *any* stack in the Shipit instance, not just the one named in the URL it was generated for.

### Finding Description
Binding claimed: `token_bearer_authorization == stack_named_in_url`.

Trace:
- `CCMenuUrlController#fetch` (`app/controllers/shipit/ccmenu_url_controller.rb:7-11`) builds `uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))` and appends `token = client.authentication_token`.
- `client` is `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` [1](#0-0) . This never sets `stack:`, so `stack_id` on the created `ApiClient` is `nil`.
- `ApiClient#authentication_token` just signs the client `id` [2](#0-1) ; it carries no stack binding at all.
- On the read side, `Shipit::Api::BaseController#stacks` would normally scope by `current_api_client.stack_id` when present: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [3](#0-2) . But since `stack_id` is always `nil` for this client, this already resolves to `Stack.all`.
- Worse, `Api::CCMenuController` doesn't even use that scoped helper: it overrides `stack` with `@stack ||= Stack.from_param!(params[:stack_id])` [4](#0-3) , completely ignoring `current_api_client.stack_id` even in the case where it happened to be set.
- The only gate is `require_permission :read, :stack` [5](#0-4) , which just checks `permissions.include?('read:stack')` globally via `ApiClient#check_permissions!` [6](#0-5)  — it has no notion of which stack is being requested.

So the equality is false both by construction (client is never stack-scoped) and by the controller override (even a stack-scoped client's binding would be ignored). Any holder of a CCMenu token can call `GET /api/stacks/:owner/:repo/:branch/ccmenu.xml?token=...` for an arbitrary `stack_id` path and get a 200 with that stack's deploy status, regardless of which stack the token was minted for.

### Impact Explanation
An attacker who obtains one leaked CCMenu URL (e.g., pasted into a public CI badge, PR description, or shared dashboard) gains standing, repeatable, unauthenticated read access to the latest deploy/rollback status (`Api::CCMenuController#show` renders `shipit/ccmenu/project` XML) for every stack hosted by that Shipit instance, not just the one it was generated for. This is an unauthorized cross-tenant read of stack state, matching the High severity category "unauthenticated read of stack state, task streams or deploy output." It does not by itself grant write/deploy/rollback capability since `permissions` only contains `read:stack`, so it does not rise to Critical.

### Likelihood Explanation
Preconditions: an authenticated Shipit user visits the stack settings page to obtain a CCMenu URL (a normal, low-friction UI feature — `app/views/shipit/stacks/settings.html.erb`), and that URL/token subsequently leaks (public CI badge, shared doc, PR description — a common real-world usage pattern for CCMenu badges). No secrets, GitHub credentials, or privileged roles are required by the attacker; they only need the leaked URL. Once obtained, the attacker can enumerate/query arbitrary `stack_id` path segments without further authorization checks, making this fully repeatable across all stacks in the instance.

### Recommendation
- When minting the CCMenu `ApiClient`, scope it to the specific stack: `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, name: "CCMenu Client (#{stack.to_param})")` so `stack_id` is set per-stack rather than shared/nil across all stacks for a user.
- Fix `Api::CCMenuController#stack` to use the base class's scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so `current_api_client.stack_id` is actually enforced.

### Proof of Concept
In `test/controllers/api/ccmenu_controller_test.rb` (or a new test):
1. Create `stack_a` and `stack_b`.
2. Sign in as a user, call `CCMenuUrlController#fetch` for `stack_a` (simulate via the route) to obtain `client.authentication_token` and the generated `ccmenu_url`.
3. Assert (equality check #1): `client.stack_id` is `nil` (or, after fix, equals `stack_a.id`) — i.e., `token_bearer_authorization != stack_named_in_url` before fix.
4. Send `GET api_stack_ccmenu_url(stack_id: stack_b.to_param, token: token)`.
5. Assert response is `200` and body contains `stack_b`'s project name — proving the token minted for `stack_a` grants read access to `stack_b`.
6. After applying the recommended fix, re-run step 4 and assert the response is `403`/`404` (insufficient permission or stack not found) for `stack_b`, and still `200` for `stack_a`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
