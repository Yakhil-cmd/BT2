### Title
Stack-scoped API client can read the CI/deploy status of any other stack via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the base `stack` lookup helper with an unscoped `Stack.from_param!(params[:stack_id])`, bypassing the stack-scoping enforcement that every other API controller relies on. An `ApiClient` created with `stack_id` set (i.e., a token meant to authorize access only to one specific stack) can be used to fetch the CI status XML of any other stack in the installation, breaking the binding between "the stack a token authorises" and "the stack it touches."

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scoped stack lookup used by every other API endpoint: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the authenticated `ApiClient` has a `stack_id` set, and `stack` resolves the requested `params[:stack_id]` only within that restricted relation. This is the mechanism that makes an `ApiClient.stack_id` a real authorization boundary (confirmed by the existing test "an api client scoped to a stack will only see that one stack" for `Api::StacksController`).

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

`require_permission :read, :stack` (line 6) only checks that the client's `permissions` array contains the generic string `"read:stack"` via `ApiClient#check_permissions!`: [3](#0-2) 

This check is entirely independent of which specific `Stack` record is being accessed — it never consults `current_api_client.stack_id`. Because `CCMenuController#stack` uses the unscoped `Stack.from_param!` (bypassing `stacks.from_param!`), any client possessing the `read:stack` permission — including one deliberately scoped to a single stack via `stack_id` — can supply an arbitrary `stack_id` in the URL and successfully load and render a different stack's build state: [4](#0-3) 

The equality this bug class targets: "the stack a token authorises" (`current_api_client.stack_id`, enforced everywhere else via `stacks`) must equal "the stack the request actually touches" (`params[:stack_id]` as resolved by `stack`). `CCMenuController` breaks this equality by resolving `stack` from the global `Stack` table instead of the client's authorized subset.

Note: this endpoint also supports authenticating via a `?token=` query parameter instead of the standard `Authorization` header (`authenticate_api_client` override, lines 33-36), which is how CCMenu-polling tools normally use these tokens — this is a legitimate, documented usage pattern (see `CCMenuUrlController`) and not itself the bug; the bug is the loss of stack scoping once authenticated.

### Impact Explanation
An `ApiClient` scoped to Stack A (e.g., issued to a third-party CI-status widget/tool for one repository) can read the latest deploy/rollback status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`) of any other stack B in the same Shipit installation, including private/internal stacks the token holder was never authorized to see. This is an unauthorized cross-stack read of deploy state — matching the High-impact category of "unauthenticated/unauthorized read of stack state or deploy output," since the token's authorization is limited to a single stack by design and that limitation is silently bypassed for this endpoint.

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` token that has the `read:stack` permission (a very common, low-privilege permission granted to CCMenu integrations specifically) — no elevated privileges, no write access, and no knowledge of secrets beyond the token itself. The attacker only needs to change `stack_id` in the request URL/params, which is a single, straightforward step. This makes the likelihood high for any deployment where stack-scoped tokens are issued for CCMenu integrations (a documented, first-class use case per `CCMenuUrlController`).

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped lookup consistent with the rest of the API surface:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This reuses `BaseController#stacks`, which already restricts the queryable set to `current_api_client.stack_id` when present, restoring the intended per-token stack scoping.

### Proof of Concept
1. As an admin, create a stack-scoped `ApiClient` for Stack A with `permissions: ["read:stack"]` and `stack_id: <Stack A id>` (this is exactly what `CCMenuUrlController#client` does automatically for the "Get CCMenu URL" feature): [5](#0-4) 
2. Obtain the resulting `authentication_token` (embedded in the CCMenu URL shown to the user).
3. Issue: `GET /api/<Stack-A-param>/cc.xml?token=<token>` — succeeds as expected, per the existing design.
4. Issue instead: `GET /api/<Stack-B-param>/cc.xml?token=<token>` where Stack B is any other stack in the installation.
5. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unscoped, and `require_permission :read, :stack` only checks the generic `"read:stack"` string permission (not tied to `stack_id`), the request succeeds and returns Stack B's `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `activity` — data the token was never authorized to access.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
