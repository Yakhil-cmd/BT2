### Title
`CCMenuController#stack` bypasses stack-scoped authorization, allowing any `read:stack` API client to read another stack's CCTray status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stacks` scopes lookups to `Stack.where(id: current_api_client.stack_id)` when a client is stack-scoped, and `#stack` calls `stacks.from_param!` to enforce that binding. `Api::CCMenuController` overrides `#stack` with `Stack.from_param!(params[:stack_id])` directly on the model class, which never consults `current_api_client.stack_id`, so a stack-scoped client with only `read:stack` permission can fetch the CCTray XML for any stack, not just the one it is bound to.

### Finding Description
The binding that should hold is: `current_api_client.stack_id == stack.id` for every stack-scoped client (unless `stack_id` is nil, meaning global access) — this is exactly what `Api::BaseController#stacks`/`#stack` implement: [1](#0-0) 

`CCMenuController` inherits from `BaseController` and declares `require_permission :read, :stack`: [2](#0-1) 

but it redefines the private `#stack` method to call `Stack.from_param!(params[:stack_id])` on the class directly, discarding the `current_api_client.stack_id` scoping entirely: [3](#0-2) 

`require_permission!` only checks that the permission string `"read:stack"` is present in `current_api_client.permissions`, and never inspects `stack_id`: [4](#0-3) 

So the call sequence `authenticate_api_client -> require_permission!(:read, :stack) -> show -> stack -> Stack.from_param!` never re-checks that the requested `stack_id` matches the client's bound `stack_id`. An attacker holding a valid `ApiClient` token restricted to stack A (with `permissions: ['read:stack']`) can request `GET /:stack_id_of_B/cc.xml?token=...` and receive stack B's build status (branch, last deploy state) — a stack it was never authorized to read.

This diverges from every other API controller in the engine (e.g. `Api::StacksController`, `Api::TasksController`, etc.) which rely on `BaseController#stack`/`#stacks` and are therefore correctly scoped.

### Impact Explanation
The vulnerability lets a caller possessing a stack-scoped API client token read CCTray XML (deploy status, latest deploy/rollback id, `ended_at`, running state) for arbitrary stacks it has no `stack_id` binding to, as long as it has any `read:stack` permission. This is an unauthenticated-for-other-tenants read of stack state — cross-tenant information disclosure of deploy/build status — matching the "High: unauthenticated read of stack state" category, since the exposed CCTray data is limited to build/deploy status rather than full task logs. It is fully repeatable: the request can be issued for every stack ID in the system since `Stack.from_param!` will resolve any known ID or `repository/environment` param regardless of the requesting client's binding.

However, this attack requires a valid, already-issued `ApiClient` token — this is not reachable by a fully unauthenticated, credential-less attacker as defined in the ruleset ("They hold no ... `ApiClient` token"). The bug is real and is a privilege-escalation-within-API-clients issue (a token minted for stack A leaking data about stack B), but under the strict "unprivileged attacker holds no API client token" precondition stated in the rules, this specific path is not exploitable by the described attacker without first obtaining any `ApiClient` token, which the ruleset excludes.

### Likelihood Explanation
Preconditions: `Shipit.disable_api_authentication` must be `false` (otherwise `UnlimitedApiClient` is used engine-wide anyway), and a `stack_id`-scoped `ApiClient` token with `read:stack` permission must exist and be known to the attacker. Given those preconditions, exploitation is trivial and repeatable — a single GET request to `/api/:stack_id/cc.xml?token=...` for any other stack ID. But per the audit's attacker model, the attacker holds no `ApiClient` token at all, so this specific bug is out of reach for the defined threat actor; it would only be relevant to a threat model where a legitimately-scoped API client is malicious or compromised, which is outside the stated "unprivileged, no ApiClient token" attacker.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited, properly-scoped lookup instead of hitting the model directly, e.g. remove the private `#stack` override entirely so it falls back to `BaseController#stack` (`stacks.from_param!(params[:stack_id])`), or explicitly scope: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id).from_param!(params[:stack_id]) : Stack.from_param!(params[:stack_id])`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (conceptual addition)
test "#show refuses to render a stack outside the client's stack_id scope" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclid) # a different existing stack
  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped',
    permissions: ['read:stack'],
    stack_id: stack_a.id,
  )
  token = scoped_client.authentication_token

  get :show, params: { stack_id: stack_b.to_param, token: token }

  # Binding under test: current_api_client.stack_id == stack.id
  assert_equal stack_a.id, scoped_client.stack_id
  refute_equal scoped_client.stack_id, stack_b.id
  assert_response :not_found # currently fails: responds 200 with stack_b's CCTray XML
end
```

This mirrors the pattern used to test `BaseController#stack` scoping in `Api::StacksController` but demonstrates that `CCMenuController` does not enforce the same `stack_id` binding.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
