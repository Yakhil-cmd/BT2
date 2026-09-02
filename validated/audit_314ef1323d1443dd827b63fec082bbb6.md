### Title
Stack-scoped API client tokens bypass their stack authorization in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` resolver from `Shipit::Api::BaseController` and, in doing so, drops the scoping that restricts a `stack`-bound `ApiClient` to the single stack it was issued for. Any valid `ApiClient` token — even one deliberately scoped to exactly one stack — can be used against the CCMenu endpoint to read the build/deploy status of *any* stack in the installation, breaking the "stack a token authorizes vs. stack it touches" binding described in the bug-class hint.

### Finding Description
`ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . The base API controller enforces this scoping through the `stacks`/`stack` helper pair:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that relies on this helper (e.g. `Api::StacksController`, `Api::OutputsController`, `Api::TasksController`) can therefore only ever resolve `stack` to a stack the presented `ApiClient` is authorized for.

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

The `require_permission :read, :stack` before_action only checks the `read:stack` *permission* on the token, not which specific stack it is bound to [4](#0-3) [5](#0-4) . So a stack-scoped token — the exact object model that exists to express "this credential authorizes stack X only" — is accepted, but the controller then serves data for whatever `stack_id` is supplied in the request, not the stack the token is bound to. This is confirmed by the test fixture `here_come_the_walrus`, which is explicitly scoped `stack: shipit` with only `read:stack` permission [6](#0-5) , yet nothing in `CCMenuController` prevents that same token from being replayed with a different `stack_id` param to view another stack's CI/deploy status.

### Impact Explanation
This breaks the authorization binding between "the stack a token was issued/authorized for" and "the stack whose data is actually returned." An attacker in possession of any single-stack, read-only CCMenu-style token can enumerate and read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state, etc., rendered by `shipit/ccmenu/project`) of every other stack managed by the Shipit instance, including stacks/repositories they were never granted access to. This matches the High-impact criterion of "unauthenticated read of stack state" in the sense that read access is obtained for stacks outside of what the credential authorizes — an authorization escalation across the API-client scoping boundary that every other API controller correctly enforces.

### Likelihood Explanation
High. No special privileges are required beyond holding any valid, even minimally-scoped, `ApiClient` token with `read:stack` permission (the least-privileged token type this system issues, e.g. the "CCMenu Client" token flow at `app/controllers/shipit/ccmenu_url_controller.rb`, or any manually issued single-stack token). The only action required is changing the `stack_id` request parameter — no code execution, no secret material, and no interaction with GitHub is needed.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, properly scoped `stacks`/`stack` helper from `Api::BaseController`, so that `Stack.from_param!` is resolved against `current_api_client`'s authorized stack scope rather than the global `Stack` relation.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to stack A with permission `read:stack` (e.g. fixture `here_come_the_walrus`, scoped to `shipit`) [6](#0-5) .
2. Using this token's `authentication_token`, issue: `GET /api/1/stacks/:other_stack_id/ccmenu?token=<token>` where `other_stack_id` refers to a different stack the client is not scoped to.
3. Observe that `CCMenuController#stack` resolves via `Stack.from_param!(params[:stack_id])` [3](#0-2)  instead of the scoped `stacks.from_param!` used elsewhere [7](#0-6) , and the response renders build/deploy status for the unauthorized stack rather than returning a 403/404.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
