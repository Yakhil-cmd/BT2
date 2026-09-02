### Title
CCMenu API endpoint lets a stack-scoped `ApiClient` token read the build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` resolver inherited from `Shipit::Api::BaseController` and looks up the target stack directly via `Stack.from_param!(params[:stack_id])` instead of the `ApiClient`-scoped `stacks` relation. This breaks the equality that should hold between "the stack(s) an `ApiClient` token authorizes" and "the stack the request actually touches," letting a CCMenu token minted for one stack read CI/build data for any other stack in the installation.

### Finding Description
`Shipit::Api::BaseController` is designed so that requests are always scoped to the stacks an `ApiClient` is allowed to see: [1](#0-0) 

`current_api_client.stack_id?` returning true means the client was created bound to a single stack (`belongs_to :stack, optional: true` on `ApiClient`), and every controller that calls the inherited `stack` helper is restricted to that one stack via `stacks.from_param!`.

`CCMenuController`, however, redefines `stack` to bypass this scoping entirely and resolve directly against the full `Stack` table: [2](#0-1) 

It also supports authenticating via a `params[:token]` query-string token (this is the intended flow, since `CCMenuUrlController` hands users a URL containing a client token for embedding in third-party CI-status tools): [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which validates a *permission string* (`"read:stack"` is present in the client's `permissions` array) but never verifies that the specific `stack_id` being requested matches the `stack_id` the `ApiClient` was scoped to: [4](#0-3) [5](#0-4) 

So the binding that should hold — `ApiClient#stack_id == requested stack_id` when `stack_id?` is true — is broken specifically in this controller, even though the base controller enforces it correctly for every other endpoint (as shown by the stack-scoping test in `stacks_controller_test.rb`): [6](#0-5) 

### Impact Explanation
An attacker who obtains (or is legitimately given, e.g. embedded in a CI tool's config, a monitoring dashboard, or a leaked URL) a CCMenu token scoped to one stack can supply an arbitrary `stack_id` parameter and retrieve build/CI status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for every other stack managed by the Shipit instance — including private/internal stacks the token holder has no read authorization for. This is an unauthenticated-relative-to-scope read of stack state, matching the "unauthorized read of stack state" High-impact category, since the token's authorization is supposed to be pinned to a single stack.

### Likelihood Explanation
Likelihood is high given the intended usage pattern: `CCMenuUrlController#fetch` generates and hands out a URL containing the raw authentication token in the query string specifically so it can be embedded in third-party CI dashboard tools (CCMenu clients), which is a use case explicitly documented for exposure outside the trusted web session. Any holder of such a URL (or anyone who can observe it in logs, browser history, referrer headers, or a misconfigured public dashboard) can trivially change the `stack_id` query parameter to enumerate other stacks; no cryptographic break is required.

### Recommendation
In `CCMenuController`, remove the local `stack` override and use the inherited, properly-scoped `stack`/`stacks` helper from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) so that a stack-scoped `ApiClient` cannot resolve any stack other than the one it was bound to. If `CCMenuController` needs this custom override for a reason (e.g., different lookup semantics), it must additionally verify `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering.

### Proof of Concept
1. A CCMenu URL is generated for `stack_a` via `CCMenuUrlController#fetch`, producing an `ApiClient` with `stack_id = stack_a.id` and `permissions = ["read:stack"]`, and a token `T` bound to that client: [7](#0-6) 
2. The resulting URL (`.../api/stacks/:stack_a/ccmenu.xml?token=T`) is embedded in a third-party CI dashboard, as intended.
3. An attacker who observes token `T` (e.g. via referrer leakage, shared dashboard, logs) requests:
   `GET /api/stacks/stack_b/ccmenu.xml?token=T`
4. `authenticate_api_client` accepts `T` (valid signature, resolves to the client scoped to `stack_a`).
5. `require_permission :read, :stack` passes because the client has `"read:stack"` in its permissions list, regardless of which stack.
6. `stack` resolves via `Stack.from_param!(params[:stack_id])` directly to `stack_b`, ignoring that the client is bound to `stack_a`.
7. The response renders `stack_b`'s build status/name/last build info — data the token was never authorized to access.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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
