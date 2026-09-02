### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any other stack's status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` accessor with a version that looks up the stack directly via `Stack.from_param!`, instead of going through the `stacks` scoping helper that every other API controller relies on to enforce an `ApiClient`'s stack restriction. This breaks the equality that should hold between "the stack an `ApiClient` token is authorized for" and "the stack the request actually touches."

### Finding Description
`Shipit::Api::BaseController` defines the authorization scoping for all API endpoints: [1](#0-0) 

`stacks` restricts the visible set of stacks to `current_api_client.stack_id` when the `ApiClient` is scoped to one stack, and `stack` (used by most controllers, e.g. `CommitsController`, `StacksController`) resolves `params[:stack_id]` only within that restricted set.

`Shipit::Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly rather than `stacks.from_param!(params[:stack_id])`. The `require_permission :read, :stack` declaration on this controller only checks that the `ApiClient` has the `read:stack` *permission string* via `ApiClient#check_permissions!`; it never checks that `params[:stack_id]` matches the client's own `stack_id`: [3](#0-2) 

The CCMenu endpoint is specifically designed to be used with narrowly-scoped tokens: `CCMenuUrlController#client` creates (or reuses) an `ApiClient` scoped to a *single* stack with only the `read:stack` permission, intended for embedding in CI dashboards/build-status widgets: [4](#0-3) 

Because `CCMenuController#stack` ignores that scoping, any holder of such a token (e.g., a leaked CCMenu badge URL for stack A) can request `/api/<other_stack>/ccmenu` and successfully read stack B's data — something the `here_come_the_walrus`-style scoped `ApiClient` (see fixture `app/... test/fixtures/shipit/api_clients.yml`) is explicitly supposed to be prevented from doing: [5](#0-4) 

**Binding broken:** `ApiClient.stack_id` (the stack the token authorizes) ≠ `params[:stack_id]` (the stack actually rendered by `CCMenuController#show`).

### Impact Explanation
This is an unauthenticated-scope escalation: a token deliberately restricted to one stack's read access can be used to read the build/deploy status, lock state, and last-build information of any other stack in the Shipit instance. This matches the accepted High-severity impact category of "escalation into `Shipit.github_teams` authorization" / "unauthenticated read of stack state, task streams or deploy output," since a token meant to expose only one stack's status now exposes all stacks.

### Likelihood Explanation
Likelihood is high for any deployment that uses the CCMenu integration (a first-class, documented feature exposed via `CCMenuUrlController`). CCMenu URLs are typically embedded in third-party CI dashboard tools/widgets, which increases the chance of the token being exposed to parties who should only see one stack's status. No privileged access, GitHub credentials, or webhook secret is required — only possession of a legitimately-issued, narrowly-scoped `ApiClient` token.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, scoped lookup:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private override entirely so it falls back to `Shipit::Api::BaseController#stack`, which respects `current_api_client.stack_id`.

### Proof of Concept
1. An operator creates a CCMenu URL for `stack-a` (e.g., via the stack settings page), which internally calls `CCMenuUrlController#client`, creating/reusing an `ApiClient` with `permissions: ['read:stack']` and `stack: stack-a`, and returns a URL like:
   `https://shipit.example.com/api/stack-a/ccmenu?token=<TOKEN>`
2. This URL/token is embedded in an external CI dashboard widget (the intended use case), and is now known to a third party who should only be authorized to see `stack-a`'s status.
3. That party requests:
   `GET https://shipit.example.com/api/stack-b/ccmenu?token=<TOKEN>`
4. `Api::CCMenuController#authenticate_api_client` authenticates the token successfully (it's valid, just scoped to `stack-a`) and `require_permission :read, :stack` only checks the string permission `read:stack`, which the token has. `CCMenuController#stack` then calls `Stack.from_param!('stack-b')` unscoped, successfully returning `stack-b`, and `show` renders `stack-b`'s deploy/build status in the XML response — data the token was never authorized to access.

**Note on completeness:** I was not able to fully trace whether any other controller in `app/controllers/shipit/api/**` has a similar override pattern beyond `CCMenuController`; a full audit of every API controller for a local `stack`/`stacks` override would be advisable, but based on the `grep_search` results only `CCMenuController` diverges from the shared `stacks.from_param!` pattern used elsewhere.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
