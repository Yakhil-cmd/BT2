Confirmed exploitable analog. Here is the finding.

### Title
Stack-scoped API tokens bypass their stack restriction via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` token scoped to a single stack (`api_client.stack_id`) can only resolve `stack` objects from that scoped subset via the private `stacks`/`stack` helpers. `Shipit::Api::CCMenuController` overrides `stack` to bypass this scoping entirely, resolving `params[:stack_id]` against the full `Stack` table instead of the token's authorized scope. Any holder of a valid `read:stack` token — even one deliberately created with `stack_id` restricted to a single stack — can read build/deploy status for every stack in the Shipit instance.

### Finding Description
`BaseController` defines the binding between a token and the stacks it may touch: [1](#0-0) 

`stacks` restricts the resolvable set to `Stack.where(id: current_api_client.stack_id)` when the token carries a `stack_id`, and `stack` is defined in terms of that restricted scope (`stacks.from_param!`). This is the intended equality: `token.stack_id == requested_stack.id` (when the token is stack-scoped).

`CCMenuController`, however, redefines `stack` independently of this scoping: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, never consulting `current_api_client.stack_id`. The controller's own `require_permission :read, :stack` before the action only checks that the token has the `read:stack` permission string in its list — it never checks that the specific `stack` object being accessed matches the token's `stack_id`: [3](#0-2) 

The system does create and rely on stack-scoped tokens elsewhere — this is exercised in tests for the `stacks` API (`an api client scoped to a stack will only see that one stack`): [4](#0-3) 

but that scoping guarantee silently does not hold for `CCMenuController#show`, which authenticates via the same `ApiClient.authenticate` mechanism (accepting the token via query string): [5](#0-4) 

This breaks the equality `token.stack_id == requested_stack.id` for this one endpoint, even though the same token is correctly restricted everywhere else in the API (stacks index/show, tasks, deploys, etc.).

### Impact Explanation
An attacker who obtains any valid stack-scoped `read:stack` API token (e.g. one deliberately handed to a low-trust integration such as a CI status dashboard for a single, non-sensitive stack) can use that token against `GET /api/stacks/:stack_id/ccmenu` for an arbitrary `stack_id` belonging to any other stack in the instance — including private/sensitive stacks the token was never meant to access — and obtain that stack's lock state, last build status/label/time and webUrl. This is an unauthorized cross-stack read of stack state, matching the "High" impact tier (unauthenticated/unauthorized read of stack state).

### Likelihood Explanation
Any party in possession of a stack-scoped `read:stack` token (a routine, low-privilege credential meant to be distributed to third-party build-status tools) can trigger this with a single unauthenticated-looking GET request; no additional privilege, secret, or session is required beyond the token itself, and stack IDs/params are easily enumerable/guessable slugs (`repo_owner/repo_name/environment`).

### Recommendation
Have `CCMenuController#stack` resolve through the same scoped `stacks` helper used by `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so stack-scoped tokens cannot be used to read data belonging to other stacks.

### Proof of Concept
1. As a legitimate user, request a CCMenu URL for stack `owner/repo-a/production` via `CCMenuUrlController#fetch`; this mints/reuses an `ApiClient` with `permissions: ["read:stack"]` and obtains its `authentication_token`.
2. Alternatively, obtain any independently-issued API token that is explicitly scoped with `stack_id` set to stack A only (as created for narrow integrations, permissions `["read:stack"]`).
3. Send `GET /api/stacks/owner/repo-b/staging/ccmenu?token=<token>` where `repo-b/staging` is a *different* stack than the one the token is scoped to.
4. `CCMenuController#authenticate_api_client` authenticates the token successfully; `require_permission :read, :stack` passes because the token has `read:stack` in its permission list; `stack` resolves `repo-b/staging` directly via `Stack.from_param!`, ignoring `current_api_client.stack_id`.
5. The response renders `repo-b/staging`'s lock/build status, even though the token was only authorized for `repo-a/production`.

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
