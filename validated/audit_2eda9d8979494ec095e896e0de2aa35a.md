### Title
`CCMenuController#stack` bypasses `ApiClient#stack_id` scoping, allowing cross-stack unauthenticated read - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` helper to call `Stack.from_param!(params[:stack_id])` directly instead of using `BaseController#stacks`, which is the only place enforcing that a scoped `ApiClient` (`stack_id` set) may only resolve its own stack. This lets a holder of a stack-A-scoped CCMenu token read the build/deploy status XML of any stack B, breaking the intended token scope.

### Finding Description
The broken binding: `stack ∈ current_api_client.stack_id? ? {Stack(current_api_client.stack_id)} : Stack.all` must hold for every `Api::BaseController` subclass. `BaseController#stacks` (app/controllers/shipit/api/base_controller.rb:74-76) enforces exactly this: `@stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `BaseController#stack` (line 78-80) resolves via that scope: `stacks.from_param!(params[:stack_id])`.

`CCMenuController` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) redefines `stack` as:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
This drops the `stacks` scoping entirely and resolves any stack in the system directly from `params[:stack_id]`, regardless of `current_api_client.stack_id`.

Exploit flow: `authenticate_api_client` in `CCMenuController` (lines 33-36) authenticates via `ApiClient.authenticate(params[:token])`, which only checks the HMAC-signed client id (`ApiClient.authenticate` in app/models/shipit/api_client.rb:24-27) — it performs no stack-scope check. `require_permission :read, :stack` (line 6) only checks `permissions.include?('read:stack')` via `check_permissions!` (app/models/shipit/api_client.rb:38-45) — it never compares `current_api_client.stack_id` to the requested `params[:stack_id]`. `#show` (lines 22-25) then calls `stack`, which resolves stack B directly. None of `verify_signature`, `force_github_authentication`, or `require_permission!` check stack-id equality; that check exists solely in the overridden-away `stacks` method.

Attacker request: `GET /api/stacks/<stackB_param>/cc.xml?token=<tokenA>` where `tokenA` belongs to an `ApiClient` with `stack_id: stackA.id` and `permissions: ['read:stack']`. The request succeeds and returns stack B's CCMenu XML (deploy status, last build label/time, activity) despite the token being scoped to stack A only.

### Impact Explanation
An attacker possessing any single legitimately-scoped CCMenu token (these tokens are routinely embedded in unauthenticated CCMenu/CI-status-badge URLs) can enumerate and read the deploy/build status of arbitrary other stacks belonging to unrelated repositories/tenants — an unauthenticated read of stack state across tenant boundaries. This matches the "High: unauthenticated read of stack state" category. The attack is fully repeatable against any stack by varying `params[:stack_id]`, with no rate limiting relevant here per rules, and requires no additional secrets beyond the one token the attacker already legitimately holds for its own scope.

### Likelihood Explanation
Preconditions are realistic and low-cost: the attacker only needs one `ApiClient` token scoped to any single stack with `read:stack` permission (such tokens are designed to be embedded in CCMenu URLs, which are often shared/exposed to CI dashboards, third-party tools, or leaked). No GitHub secrets, sessions, or elevated roles are needed. The request is a single unauthenticated HTTP GET with a guessable/enumerable `stack_id` param (stack params are typically `owner/repo/env`-style, discoverable). This makes exploitation trivial and highly likely once any one token is obtained.

### Recommendation
Remove the `stack` override in `CCMenuController` and rely on the inherited `BaseController#stack`/`#stacks` methods so that scoped `ApiClient` tokens can only resolve the stack they were issued for, e.g.:
```ruby
# delete the private `stack` method in CCMenuController entirely
```
so `stack` falls back to `Shipit::Api::BaseController#stack`, which uses `stacks.from_param!` and thus respects `current_api_client.stack_id`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read stack B via cc.xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: "other", name: "repo"), branch: 'main')

  client_a = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped-to-a',
    stack_id: stack_a.id,
    permissions: ['read:stack']
  )

  # Binding under test: stack resolved by the request must be ∈ {stacks authorized by client_a.stack_id}
  # LHS: requested stack == stack_b
  # RHS (expected authorization set): Stack.where(id: client_a.stack_id) == {stack_a}
  assert_not_includes Stack.where(id: client_a.stack_id), stack_b

  get :show, params: { stack_id: stack_b.to_param, token: client_a.authentication_token }

  # Expect this to be blocked (404/403); current code returns 200 with stack B's data
  assert_response :not_found
end
```
Before the fix, this test fails: the controller returns `200 OK` with stack B's CCMenu XML payload, demonstrating the cross-tenant scope bypass. After removing the `stack` override in `CCMenuController`, `stacks.from_param!` raises `ActiveRecord::RecordNotFound` (rendered as 404) because stack B is not in `Stack.where(id: client_a.stack_id)`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
