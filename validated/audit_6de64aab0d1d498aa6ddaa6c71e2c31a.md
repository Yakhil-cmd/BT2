## Title
Cross-stack authorization bypass in CCMenu API — token issued for one stack authorizes read access to every stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The CCMenu XML feed feature is designed to hand out a narrowly-scoped, read-only credential for a *single* stack, meant to be embedded in external, low-trust consumers (CI dashboard tools, badges, intranet monitors). That "one token → one stack" binding is broken in two independent ways, and together they let anyone holding a CCMenu URL for stack A read the build/deploy status of any other stack in the Shipit installation, without ever authenticating as a user.

### Finding Description
`CCMenuUrlController#client` mints the `ApiClient` used for the CCMenu feed but never assigns it to the requesting stack: [1](#0-0) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

`stack:` is never passed into `create_with`/`find_or_create_by!`, so `ApiClient#stack_id` is left `nil`. `Api::BaseController#stacks` treats an absent `stack_id` as "unscoped, authorize all stacks": [2](#0-1) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```

Additionally, and independently, `Api::CCMenuController` doesn't even use this `stacks` scoping helper. It overrides `stack` to load directly from the request parameter: [3](#0-2) 

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

`require_permission :read, :stack` only checks `ApiClient#check_permissions!`, which merely verifies the string `"read:stack"` is present in `permissions` — it never compares the requested `stack_id` param against the client's own `stack_id`: [4](#0-3) 

The binding that should hold is:
`stack_authorized_by(token) == stack_actually_served_for(params[:stack_id])`

Before a token is minted for stack A, only stack A's status is intended to be exposed by that token. After minting, because (1) the `ApiClient` is created with `stack_id = nil` and (2) `CCMenuController#stack` ignores any per-client stack scoping entirely, the equality fails: the token authorizes and serves **every** stack whose `stack_id`/slug is supplied in the URL, not just the stack the URL was generated for.

### Impact Explanation
The CCMenu token is explicitly a low-trust, externally-shared secret — `CCMenuUrlController#fetch` builds a URL with the token embedded in the query string specifically so it can be pasted into third-party CI dashboard software: [5](#0-4) 

Anyone who obtains one such URL (e.g., from a shared dashboard config, a leaked bookmark, or a public README) can swap `stack_id` in the request path to `Api::CCMenuController#show` for any other stack in the installation and read that stack's name, last build status/label/time and web URL — none of which they were ever granted access to. This is an unauthenticated (from the app's user-auth perspective) cross-stack read of stack state, matching the "unauthenticated read of stack state ... or deploy output" High-severity class.

### Likelihood Explanation
Any user who has legitimately generated a CCMenu URL for a stack they can see already possesses a fully functional token; no privileged access, GitHub credentials, or session is required to exploit this — only changing a URL parameter. Because CCMenu URLs are designed to be embedded in external tools, they routinely leave the trust boundary of the Shipit UI, making leakage and reuse likely in practice.

### Recommendation
- In `CCMenuUrlController#client`, scope the created/found `ApiClient` to the requesting stack, e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack:)`, and include `stack:` in `create_with` as well so lookups don't collide across stacks for the same user.
- In `Api::CCMenuController`, stop bypassing the shared scoping helper — use the same `stacks` method as `Api::BaseController`/`Api::StacksController` (i.e., `stacks.from_param!(params[:stack_id])`) so that a client's `stack_id` restriction (when present) is actually enforced.
- Consider rejecting/deprecating unscoped (`stack_id: nil`) `read:stack` clients being usable against arbitrary stacks by default, requiring an explicit "all stacks" permission distinct from a per-stack token.

### Proof of Concept
1. As a legitimate but unprivileged user with access to Stack A, call `GET /stacks/:owner/:repo/:env/ccmenu_url` (route served by `CCMenuUrlController#fetch`) to obtain a CCMenu URL such as `https://shipit.example.com/api/stacks/owner-a/repo-a/env-a/ccmenu.xml?token=<TOKEN>`.
2. Confirm `ApiClient.find_by(name: 'CCMenu Client', creator: current_user).stack_id` is `nil` (per `CCMenuUrlController#client`).
3. Reuse `<TOKEN>` against a different, otherwise inaccessible stack: `GET /api/stacks/owner-b/repo-b/env-b/ccmenu.xml?token=<TOKEN>`.
4. Observe `Api::CCMenuController#show` succeeds and returns Stack B's live build/deploy status, even though the token was only ever issued for Stack A and the requesting user has no access relationship to Stack B.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
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
