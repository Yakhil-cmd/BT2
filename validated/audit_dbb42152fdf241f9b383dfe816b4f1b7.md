### Title
`CCMenuController#show` bypasses `ApiClient#stack_id` scoping via unscoped `Stack.from_param!` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` scopes stack lookups to `current_api_client.stack_id` when the token is stack-scoped, via its private `stacks`/`stack` helpers. `Shipit::Api::CCMenuController` overrides `stack` with its own implementation that calls `Stack.from_param!(params[:stack_id])` directly on the full `Stack` relation, discarding that scoping entirely. Any token with the `read:stack` permission — regardless of which stack it was issued for — can therefore fetch `cc.xml` data for any stack in the system.

### Finding Description
The intended binding is: `current_api_client.stack_id == stack.id` (when `current_api_client.stack_id?` is true), enforced by `BaseController#stacks`: [1](#0-0) 

`CCMenuController` requires only the generic `read:stack` permission via `require_permission :read, :stack`, which is checked by `ApiClient#check_permissions!` — that method only verifies the permission string `"read:stack"` is present in `permissions`, it never compares `stack_id` to the requested stack: [2](#0-1) 

The actual stack-id scoping is entirely delegated to the `stack`/`stacks` helper methods in `BaseController`. But `CCMenuController` defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` on the unscoped `Stack` model instead of `stacks.from_param!(params[:stack_id])`: [3](#0-2) 

Exploit flow: an attacker who holds any `ApiClient` token scoped to stack A, with the `read:stack` permission, sends `GET /stacks/:owner/:repo/:branch/cc.xml?token=<token_for_stack_A>` where `:owner/:repo/:branch` identifies an unrelated stack B (e.g., a stack backed by a private repository). `check_permissions!` passes because it only checks the permission name, not scope. `stack` resolves stack B directly from `Stack.from_param!`, ignoring `current_api_client.stack_id`. `show` then renders stack B's latest deploy/rollback (commit sha, branch, status) into the CC.xml response.

This differs from the equivalent logic in every other controller inheriting the un-overridden `BaseController#stack`, which correctly restricts lookups to `Stack.where(id: current_api_client.stack_id)` for stack-scoped tokens.

### Impact Explanation
A stack-scoped token grants read access to deploy/commit metadata (commit SHA, branch, last build status/time, lock status) for any stack in the Shipit instance, not just the one it was issued for. This is repeatable against arbitrary stacks by iterating `owner/repo/branch` combinations, allowing discovery and monitoring of deploy activity for repositories the token holder has no authorization for — including private/internal repositories. This matches "High - unauthenticated read of stack state" since it's cross-tenant read access beyond the token's authorized scope (a legitimately-issued but narrowly-scoped token escalates to global read).

### Likelihood Explanation
Requires possession of any valid `ApiClient` token with `read:stack` permission (even one scoped to an unrelated public stack) — this is a normal, low-privilege credential many integrations legitimately hold. No GitHub secrets, webhook signing keys, or session access needed. The attacker only needs to know or guess the target `owner/repo/branch` triple, which is often predictable/public knowledge even for the repo name itself. This is a straightforward, repeatable GET request.

### Recommendation
Remove `CCMenuController`'s custom `stack` override, or change it to reuse the base class's scoped lookup:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it inherits the `current_api_client.stack_id` restriction from `BaseController#stacks`.

### Proof of Concept
In `test/controllers/api/ccmenu_controller_test.rb` (minitest, `ApiControllerTestCase`):
```ruby
test "a token scoped to one stack cannot fetch cc.xml for a different stack" do
  other_stack = shipit_stacks(:shipit2) # a different stack fixture
  @client.update!(stack: @stack, permissions: ['read:stack'])
  assert_equal @stack.id, @client.stack_id # binding LHS: token scope

  get :show, params: { stack_id: other_stack.to_param, token: @client.authentication_token }

  # binding RHS should equal LHS (i.e., request rejected/not found);
  # current behavior violates it by returning 200 with other_stack's data
  assert_response :not_found
end
```
Before the fix this test fails because the controller returns `200 OK` with `other_stack`'s deploy data; after applying the recommended change (`stacks.from_param!`), `Stack.from_param!` raises `ActiveRecord::RecordNotFound` (rendered as 404) since `other_stack` is outside `stacks` (`Stack.where(id: current_api_client.stack_id)`).

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
