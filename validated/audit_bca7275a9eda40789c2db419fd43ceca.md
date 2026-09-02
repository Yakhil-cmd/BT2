Confirmed: `here_come_the_walrus` fixture demonstrates that `ApiClient` records can be scoped to a specific `stack` (`belongs_to :stack, optional: true`), and `Api::BaseController#stacks`/`#stack` enforce that scope via `stacks.from_param!(params[:stack_id])`. `Api::CCMenuController` overrides `#stack` with an unscoped `Stack.from_param!(params[:stack_id])`, so a token scoped to one stack can be used to read build/deploy status of any other stack.

### Title
Stack-scoped API token bypasses its stack restriction in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor inherited from `Shipit::Api::BaseController` with an unscoped lookup, breaking the binding between "the stack an `ApiClient` token is authorized for" and "the stack the token can actually query."

### Finding Description
`Api::BaseController` scopes stack lookups to the authenticated client: [1](#0-0) 
`current_api_client.stack_id?` gates a `Stack.where(id: current_api_client.stack_id)` restriction so a stack-scoped `ApiClient` (e.g. fixture `here_come_the_walrus`, which has `stack: shipit` and only `read:stack`) can only resolve stacks belonging to it. This scoping is exactly the "stack a token authorises" binding.

However, `Api::CCMenuController` defines its own private `stack` method that ignores this scoping entirely: [2](#0-1) 
It calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(...)`, and `#show` then renders that unscoped stack's deploy/build data: [3](#0-2) 

The controller also supports token-in-query-string authentication (as designed for CCMenu/CI dashboard tools), further widening exposure since the token can be shared in a URL: [4](#0-3) 

`require_permission :read, :stack` only checks that the *permission string* `read:stack` is present in `ApiClient#permissions` via `check_permissions!`; it never checks the `stack_id` scope: [5](#0-4) 

So the equality that should hold — "stack authorized by the token" == "stack touched by the request" — is broken specifically in this one controller, even though the same invariant is correctly enforced in every other `Api::*Controller` that relies on the inherited `stack`/`stacks` methods (e.g. `Api::DeploysController`, `Api::TasksController`).

### Impact Explanation
An attacker who legitimately possesses (or leaks/shares, since it can be passed as a URL query parameter) a CCMenu-style API token that was intentionally scoped to a single, non-sensitive stack can use that same token to read `lastBuildStatus`, `lastBuildLabel`, lock state, and deploy/rollback history for **any** stack in the Shipit instance, including stacks the token owner was never granted access to. This is an unauthenticated-for-other-stacks read of stack state/build status via a token whose whole purpose (per `CCMenuUrlController`, which mints per-stack "CCMenu Client" tokens) was to be limited to one stack. This matches the report's "escalation into `Shipit.github_teams` authorization" / "unauthenticated read of stack state" impact bucket at High severity for the affected resource, though the blast radius is limited to read access on the CCMenu XML endpoint (not write, deploy, or credential exfiltration), so it sits at the lower end of that category.

### Likelihood Explanation
Likelihood is moderate: exploitation requires possession of any valid, even narrowly-scoped, `ApiClient` token (Basic-Auth header or `?token=` query param) — no privileged account is otherwise needed, and the whole intended use case for such tokens (CCMenu build-status widgets embedded in third-party tools) increases the odds that a token leaks via logs, browser history, or a shared CI dashboard URL. Once such a token is obtained, exploitation is a single unauthenticated-parameter change (`stack_id`) with no further guessing beyond knowing another stack's `owner/name/environment` path, which is often public (mirrors the target repo owner/name).

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it to call the inherited `stacks.from_param!(params[:stack_id])`) so the CCMenu endpoint enforces the same `ApiClient#stack_id` scoping as every other API controller. Add a regression test asserting that a token created with a `stack_id` cannot fetch CCMenu data for a different stack.

### Proof of Concept
1. As `walrus`, create (or use fixture) an `ApiClient` scoped to `stack: shipit` with only `permissions: ['read:stack']` (e.g. `here_come_the_walrus` in `test/fixtures/shipit/api_clients.yml`) — this is exactly what `CCMenuUrlController#client` mints per-stack.
2. Authenticate to `Api::CCMenuController#show` using that token's `authentication_token`, but pass a **different** stack's param, e.g.:
   `GET /api/stacks/some-other-owner/some-other-repo/production/ccmenu.xml?token=<here_come_the_walrus_token>`
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (unscoped) rather than `stacks.from_param!(...)`, the request succeeds and returns build/deploy status XML for `some-other-owner/some-other-repo`, even though the token's `ApiClient#stack_id` only authorizes the original `shipit` stack.

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
