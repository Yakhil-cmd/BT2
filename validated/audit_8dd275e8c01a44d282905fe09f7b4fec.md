### Title
`Shipit::Api::CCMenuController#stack` bypasses `current_api_client.stack_id` scoping by calling `Stack.from_param!` instead of `stacks.from_param!` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::BaseController` restricts an `ApiClient` scoped to a single stack via `#stacks`, which every other subclass uses through `#stack` (`stacks.from_param!(params[:stack_id])`). `CCMenuController` overrides `#stack` and calls the unscoped `Stack.from_param!(params[:stack_id])` directly, so a token created with `stack_id: A` can be used to fetch CC.xml data for any other stack B by simply passing B's id/param, regardless of the token's `stack_id` restriction.

### Finding Description
The intended binding is: `current_api_client.stack_id? ? (accessible stack ∈ Stack.where(id: current_api_client.stack_id)) : (accessible stack ∈ Stack.all)`, enforced by `Shipit::Api::BaseController#stacks`/`#stack`: [1](#0-0) 

`Api::StacksController` and other subclasses inherit this `#stack` method unchanged, so they always resolve through `stacks.from_param!`, which restricts lookup to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped.

`Shipit::Api::CCMenuController` overrides `#stack` and instead calls the bare class method `Stack.from_param!(params[:stack_id])`, entirely bypassing the `stacks` scope: [2](#0-1) 

`#authenticate_api_client` in `CCMenuController` also authenticates via `params[:token]` (query string), consistent with CCMenu clients, but this does not change the stack-scoping problem — `current_api_client.stack_id` is set correctly to A, it's just never consulted.

`ApiClient#check_permissions!` only checks whether the operation/scope string (e.g. `read:stack`) is in the permissions list; it has no concept of *which* stack, so `require_permission :read, :stack` in `CCMenuController` does not add any stack-ownership check: [3](#0-2) 

Exploit flow: an operator creates an `ApiClient` scoped to stack A (`stack_id: A.id`) via `Api::ApiClientsController`, believing it can only see/report on stack A. The attacker who holds that token issues `GET /api/stacks/:any/cc.xml?token=<tokenA>&stack_id=<stackB_param>`. `authenticate_api_client` accepts the token (valid signature, belongs to client with `stack_id == A`). `#stack` then resolves `Stack.from_param!(params[:stack_id])` against the global `Stack` table with no `WHERE id = A.id` filter, returning stack B (a stack belonging to a different repository the token was never granted access to). The `show` action renders CC.xml with B's `deploys_and_rollbacks.last`, exposing B's build status, last build label, and web URL.

No other guard intercepts this: `verify_signature`/webhook checks are irrelevant (this is a token-authenticated API GET, not a webhook), `force_github_authentication` doesn't apply to `Api::BaseController` (it's a separate session-auth concern), and there is no model validation that ties a `Stack` lookup to an `ApiClient`'s `stack_id` — that binding is enforced only at the controller layer via `#stacks`, which `CCMenuController` skips.

### Impact Explanation
Each request lets the attacker read cross-tenant/cross-repository stack state (build status, last build label/time, web URL) for any stack in the Shipit install, using a token that was provisioned for a single, unrelated stack. This is repeatable for every stack id/slug in the system (enumerable via `to_param`, typically `owner/repo/branch`), giving unauthenticated (relative to the target stack) read access to arbitrary stacks' deploy status. This matches "High - escalation ... unauthenticated read of stack state" per the provided severity taxonomy, since the token holder is unauthorized for any stack other than A but can read state for all stacks.

### Likelihood Explanation
Preconditions: the attacker needs *some* stack-scoped `ApiClient` token (issued legitimately for stack A, e.g. leaked, or self-issued if the attacker is themselves a limited API client owner in a multi-tenant Shipit deployment) and needs to know or guess another stack's `to_param`/id (stack params are predictable, based on `owner/repo/branch`, not secret). No GitHub secrets, session, or elevated privileges are required beyond possessing one valid but narrowly-scoped API token. This is a low-cost, fully repeatable read against arbitrary stacks, making it highly feasible in any multi-tenant/multi-team Shipit deployment that uses stack-scoped `ApiClient` tokens for CCMenu integration.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve via the scoped helper, matching `BaseController`'s pattern:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores enforcement of `current_api_client.stack_id` for CCMenu requests, consistent with `Api::StacksController` and all other `BaseController` subclasses.

### Proof of Concept
Minitest (in `test/controllers/api/ccmenu_controller_test.rb`, though actual file lives under `test/**` which is excluded from remediation scope but is the natural location for the regression test):
1. Create `stack_a = shipit_stacks(:shipit)` and `stack_b = Stack.create!(repository: Repository.create!(owner: 'other', name: 'repo'), branch: 'main')`.
2. Create `client = ApiClient.create!(creator: shipit_users(:walrus), name: 'scoped', permissions: ['read:stack'], stack_id: stack_a.id)`.
3. `get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }`.
4. Assert (bug, current behavior): `assert_response :ok` and `assert_payload 'name', stack_b.to_param` — i.e., stack B's data is returned despite the token being scoped to stack A.
5. Assert (expected/fixed behavior): `assert_response :not_found` (or `:forbidden`), because `stack_b ∉ Stack.where(id: client.stack_id)`.

This directly demonstrates that `current_api_client.stack_id == stack_a.id` is never checked against the requested `stack_b`, confirming the broken binding.

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
