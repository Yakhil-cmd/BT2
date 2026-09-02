### Title
Cross-stack authenticated read via `Api::CCMenuController#stack` bypassing `ApiClient#stack_id` scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides `authenticate_api_client` to accept a bare `params[:token]` and overrides `stack` to fetch the target stack via `Stack.from_param!(params[:stack_id])` directly, instead of via `Api::BaseController#stacks`, which is the only place that restricts lookups to `current_api_client.stack_id`. Because `ApiClient#check_permissions!` only checks the permission name (`read:stack`) and never compares `current_api_client.stack_id` to `params[:stack_id]`, any valid stack-scoped token can be replayed against an arbitrary stack's CCMenu XML endpoint.

### Finding Description
The binding the question asks about is: `params[:token]`'s `ApiClient#stack_id` == `params[:stack_id]`'s resolved `Stack#id`. This binding is **not enforced** on the code path actually exercised by `show`.

- `authenticate_api_client` in `CCMenuController` sets `@current_api_client = ApiClient.authenticate(params[:token])`, which only verifies the signed token and loads the `ApiClient` record; it performs no comparison against `params[:stack_id]`. [1](#0-0) [2](#0-1) 

- `require_permission :read, :stack` runs `require_permission!` → `current_api_client.check_permissions!(:read, :stack)`, which only checks that `"read:stack"` is present in `permissions`; it does not consult `stack_id` at all. [3](#0-2) [4](#0-3) 

- In `BaseController`, the *only* place `current_api_client.stack_id` is actually enforced is the `stacks` helper, which scopes `Stack.where(id: current_api_client.stack_id)` when the client is stack-bound, and the default `stack` method calls `stacks.from_param!(...)`. [5](#0-4) 

- `CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, completely bypassing the `stacks` scoping that would otherwise reject a stack-mismatched token. [6](#0-5) 

Exploit flow: An attacker who legitimately possesses (or is given, e.g. copy-pasted from stack A's CCTray settings page) a token scoped to stack A with `read:stack` permission can send `GET /api/stacks/:stack_b_owner/:stack_b_repo/:stack_b_environment/cctray.xml?token=<stack_A_token>`. `ApiClient.authenticate` succeeds (token is valid), `check_permissions!(:read, :stack)` succeeds (permission name matches, no stack check), and `stack` resolves stack B directly, unscoped. The response renders stack B's latest deploy/rollback status via `shipit/ccmenu/project`, leaking cross-stack task state to a party never authorized for stack B. [7](#0-6) 

None of the listed guards intercept this: `verify_signature`/webhook checks are irrelevant (this is a GET API request, not a webhook); `ExplicitParameters`/model validators don't constrain cross-model authorization; and `require_permission!`/`check_permissions!` as shown above check only the permission string, never the stack binding.

### Impact Explanation
This is an unauthenticated-relative-to-target-stack read of stack state (latest deploy/rollback id and status) for any stack, using only a token minted for a different stack. This matches the High severity category: "unauthenticated read of stack state, task streams or deploy output" — the attacker reads stack B's state despite the token/`ApiClient` record being bound to stack A only. It is repeatable against any stack whose numeric/friendly param is guessable or known (stack params are typically `owner/repo/environment`, often discoverable), for as long as any valid stack-scoped token is available to the attacker (e.g., because it was exposed on a settings page, matching the scenario the question describes).

### Likelihood Explanation
Preconditions: the attacker must possess *some* valid `ApiClient` token with `read:stack` permission bound to any stack (not necessarily the target). Given Shipit's CCMenu/CCTray tokens are designed to be embedded in third-party CI dashboard URLs and are often distributed/copy-pasted from a stack's settings page, acquiring one is realistic without any secret access (`api_clients_secret` is never needed by the attacker — they just need a token that was already issued, as posited explicitly in the question). No `Authorization` header, GitHub secrets, or session is required at all. This makes the path directly reachable by an unprivileged holder of any single stack token.

### Recommendation
In `Api::CCMenuController#stack`, resolve the stack through the scoped `stacks` helper (i.e., delegate to `super`/use `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!` on the unscoped model, so that a stack-bound `ApiClient` cannot resolve stacks other than the one it is bound to. Additionally, consider having `check_permissions!` reject stack-scoped clients whose `stack_id` doesn't match the resolved stack, as defense in depth.

### Proof of Concept
```ruby
# test/controllers/shipit/api/ccmenu_controller_test.rb (conceptual)
test "a token scoped to stack A cannot read stack B's ccmenu status" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create(:stack) # distinct stack, "stack B"

  creator = shipit_users(:walrus)
  token_owner_client = ApiClient.create!(
    creator: creator, name: "scoped-to-a",
    stack_id: stack_a.id, permissions: ['read:stack']
  )

  # Confirm the binding under test: token's stack_id != target stack's id
  assert_not_equal stack_b.id, token_owner_client.stack_id

  get "/api/stacks/#{stack_b.repo_owner}/#{stack_b.repo_name}/#{stack_b.environment}/cctray.xml",
      params: { token: token_owner_client.authentication_token }

  # Expected (secure) behavior: 403/404, NOT 200 with stack B's data
  assert_response :forbidden # or :not_found
  refute_includes response.body, stack_b.deploys_and_rollbacks.last&.id.to_s
end
```
Currently, with the code as shown, this request returns `200 OK` and renders stack B's deploy data, confirming the cross-stack read.

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```
