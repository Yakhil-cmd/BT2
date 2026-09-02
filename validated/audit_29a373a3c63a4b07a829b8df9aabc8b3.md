### Title
CCMenu API client is created without a stack scope, allowing a leaked CCMenu token to read build/deploy status of any stack - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
The CCMenu URL generator creates an `ApiClient` intended to expose read-only CI/CD status for a single stack, but the client record is never scoped to that stack. Combined with `Api::CCMenuController` resolving the target stack solely from the request parameter, any valid CCMenu token can be replayed against an arbitrary `stack_id` to read that other stack's build/deploy status, breaking the intended binding "stack the token authorizes == stack the token can be used against."

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` scoped with `permissions: %w[read:stack]` but does not set the `stack` association: [1](#0-0) 

Because `stack:` is never passed to `create_with`/`find_or_create_by!`, the resulting `ApiClient#stack_id` is `nil`. In `Api::BaseController`, the scoping helper explicitly treats a client with no `stack_id` as unscoped and grants access to **all** stacks: [2](#0-1) 

`Api::CCMenuController` doesn't even go through that helper — it resolves the stack directly from `params[:stack_id]` with no scoping at all: [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which merely checks that `"read:stack"` is present in the client's `permissions` array — it is not stack-specific: [4](#0-3) 

So the equality that should hold — *the stack a CCMenu token authorizes == the stack the CCMenu endpoint acts on* — is broken:
- **Intended (left side):** the token minted by `CCMenuUrlController#fetch` for stack A should only authorize reads of stack A's status (that's the entire premise of embedding a per-stack CI status URL in an external CI dashboard tool).
- **Actual (right side):** because `stack_id` is `nil` on the `ApiClient` record, and `CCMenuController#stack` blindly trusts `params[:stack_id]`, the same token can be used to fetch `Api::CCMenuController#show` for stack B, C, ... any stack in the installation.

### Impact Explanation
This is an unauthenticated-boundary-crossing read: a token that a user/embed intends to scope to one project's build status becomes a global, unscoped credential that discloses deploy/build state (`lastBuildStatus`, `activity`, lock status, `webUrl`, build timestamps/labels) for every stack managed by the Shipit instance. Because CCMenu URLs are explicitly designed to be embedded in third-party CI dashboard tools (i.e., handed to less-trusted external consumers/services), a leak of one such URL (log, dashboard config, proxy, browser history, etc.) escalates into disclosure of every stack's deploy state — matching the "unauthenticated read of stack state ... deploy output" High-severity bucket.

### Likelihood Explanation
Likelihood is Medium: no privileged Shipit session or GitHub credential is required — only possession of a previously-issued CCMenu URL/token (which is by design meant to be shared with external, less-trusted tooling). Any holder of one such token can trivially enumerate other stacks by substituting `stack_id` in the request, since `Stack.from_param!` accepts any valid stack identifier/param and there is no per-token allow-list check.

### Recommendation
- Pass `stack:` into `ApiClient.create_with(...)`/`find_or_create_by!` in `CCMenuUrlController#client` so the token is actually bound to the requesting stack, and include `stack` in the `find_or_create_by!` lookup key (otherwise a second stack's request could reuse/collide with the first client record).
- In `Api::CCMenuController#stack`, resolve the stack through the shared `stacks` scoping helper (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped client cannot be replayed against other stacks.

### Proof of Concept
1. As an authenticated Shipit user with access to Stack A, visit Stack A's settings page, which triggers `CCMenuUrlController#fetch` and returns a `ccmenu_url` containing a `token` query parameter for an `ApiClient` with `permissions: ["read:stack"]` and `stack_id: nil`. [5](#0-4) 
2. Take that token and call `GET /api/<stack_B_owner>/<stack_B_name>/<stack_B_env>/ccmenu.xml?token=<token>` for Stack B, a stack the token holder was never granted access to.
3. `Api::CCMenuController#authenticate_api_client` authenticates the token successfully, `require_permission :read, :stack` passes because `"read:stack"` is present, and `stack` resolves Stack B directly from `params[:stack_id]` with no ownership check. [6](#0-5) 
4. The response renders Stack B's `lastBuildStatus`, `activity`, `lastBuildTime`, lock state, etc., confirming cross-stack disclosure via a token intended to be scoped to Stack A only.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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
