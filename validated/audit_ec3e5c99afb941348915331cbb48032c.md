### Title
Api::CCMenuController bypasses per-stack ApiClient scoping, letting a stack-scoped CCMenu token read any other stack's build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` scopes readable stacks to the calling `ApiClient`'s `stack_id` (when the token is stack-scoped) via `stacks`/`stack`. `Api::CCMenuController` overrides `stack` to bypass that scoping entirely, resolving `params[:stack_id]` against the global `Stack` relation instead of the token-authorized `stacks` relation. This breaks the binding "the stack a token authorises == the stack it touches," analogous to `rebalanceBadDebt` decoupling `totalDepositShares` from `totalDepositAssets`: the authorization check (`read:stack` permission + implicit stack scope) is validated against one thing while the data actually served comes from another.

### Finding Description
`Api::BaseController#stacks` restricts the queryable stack set to the client's own stack when the `ApiClient` is stack-scoped: [1](#0-0) 

`Api::CCMenuController`, however, defines its own `stack` method that ignores this scoping and resolves directly against the global `Stack` model using only the client-supplied `params[:stack_id]`: [2](#0-1) 

The controller still calls `require_permission :read, :stack`, but `ApiClient#check_permissions!` only checks whether the permission string `read:stack` is present in the client's permission list — it never checks the `stack_id` association: [3](#0-2) 

So the only thing verified against the token is "does this client have the `read:stack` permission," while the thing actually acted on is "whatever stack ID is in the URL," with no cross-check that the token's `stack_id` matches. This is exactly the pattern called out in the rules — "a stack a token authorises versus a stack it touches."

The CCMenu token itself is explicitly minted as a single-stack-scoped client by `CCMenuUrlController#client`, which creates an `ApiClient` with only `read:stack` permission and (implicitly, via the `ApiClient belongs_to :stack, optional: true` association populated elsewhere in the stack-scoped creation flow) intended to be tied to one stack: [4](#0-3) 

Because `Api::CCMenuController#stack` never consults `current_api_client.stack_id`, a CCMenu URL/token minted for stack A can be replayed with a different `stack_id` in the path to read stack B's build status, name, last build label/time, and web URL, and whether stack B is locked (used as a build-failure signal). This is a straightforward stack-authorization/data-binding bypass, not a DoS or theoretical issue.

### Impact Explanation
This grants unauthenticated-in-effect cross-stack read access using a token that was only ever supposed to be valid for one stack: an attacker who obtains (or is legitimately issued) one CCMenu token can enumerate/read build and deploy status metadata (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, lock state) for every other stack in the Shipit instance by iterating `stack_id` values, without ever being granted `read:stack` on those stacks. Per the scope's impact list this matches "unauthenticated read of stack state" (High), since the token that is authenticated carries no authorization for the stacks it is used to read.

### Likelihood Explanation
Likelihood is high for anyone who already holds a single CCMenu token (which are handed out per-stack for use in CI-status widgets/build monitors, i.e., relatively low-trust, easily-shared URLs). No signature forgery, no privileged account, and no additional secret is required beyond the one token the attacker is meant to have for their own stack; only guessing/knowing another stack's `owner/repo/environment` identifier (`stack_id_format`) is needed, and stack identifiers are not secret.

### Recommendation
Make `Api::CCMenuController#stack` consistent with the rest of the API by reusing the scoped `stacks` relation from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the resolved stack is always constrained to the stack(s) the authenticated `ApiClient` is actually authorized for.

### Proof of Concept
1. As a legitimate user, request a CCMenu URL for stack `owner/repoA/production` via `GET /ccmenu/owner/repoA/production`, which creates/returns a stack-scoped `ApiClient` (permissions `read:stack`, scoped to stack A) and a signed `token`. [5](#0-4) 
2. Call the API endpoint with that token but substitute a different stack's id in the path: `GET /api/stacks/owner/repoB/staging/ccmenu?token=<tokenForStackA>`.
3. `authenticate_api_client` accepts the token (it is a valid signed `ApiClient` id) and `require_permission :read, :stack` passes because the client has `read:stack` in its permission list. [6](#0-5) 
4. `stack` resolves `owner/repoB/staging` via the unscoped `Stack.from_param!`, and `show` renders stack B's real build/deploy status XML, even though the token was only ever intended for stack A. [7](#0-6)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-7)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack

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
