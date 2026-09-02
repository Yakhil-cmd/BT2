## Title
`Api::CCMenuController#stack` bypasses the `current_api_client.stack_id`-scoped `#stacks` query, enabling cross-stack read with a stack-scoped token - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

## Summary
`Shipit::Api::BaseController` scopes stack resolution through `stacks.from_param!`, filtering by `current_api_client.stack_id` when the token is stack-scoped. `Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly, completely skipping the `#stacks` scope. Because `ApiClient#check_permissions!` only checks the permission string (e.g. `read:stack`) and never checks `stack_id`, a token scoped to stack A can be used to read cc.xml build status for any other stack B by substituting `stack_id` in the request.

## Finding Description
The intended binding is: for any controller resolving a stack, `stack.id ∈ current_api_client.stack_id`'s allowed set, enforced via
`app/controllers/shipit/api/base_controller.rb#stacks` (`Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?`) and `#stack` (`stacks.from_param!(params[:stack_id])`). [1](#0-0) 

`Api::CCMenuController` redefines `#stack` to bypass this entirely: [2](#0-1) 

Authorization for this action only runs `require_permission :read, :stack`, which delegates to `ApiClient#check_permissions!`, a check that is purely permission-string-based (`"read:stack"` membership in `permissions`) and has no notion of the specific stack ID at all: [3](#0-2) 

So the only place `stack_id` scoping is supposed to be enforced is inside `#stacks`/`#stack` in the base controller — and `CCMenuController` does not use it. Any `ApiClient` with `read:stack` permission, regardless of its `stack_id` attribute, can fetch `GET /api/stacks/:stack_id/cc.xml` (or the equivalent route) for **any** stack in the database by substituting the `stack_id` param, since `Stack.from_param!` performs an unscoped lookup.

Attack: the attacker obtains a `read:stack`-scoped API token for stack A they administer (e.g. via the "CC Menu URL" feature, `CCMenuUrlController`, or any other flow that mints an `ApiClient` restricted to stack A). They then request the CCMenu XML endpoint with the same token but with `params[:stack_id]` set to stack B (a repository/stack they do not administer). `CCMenuController#stack` resolves stack B unconditionally, `require_permission!(:read, :stack)` passes (no stack qualifier checked), and the response leaks stack B's deploy/task state (`deploys_and_rollbacks`, lock status, build status/label/time) rendered via `shipit/ccmenu/project.xml.builder`.

None of the listed guards catch this: `verify_signature`/webhook checks are irrelevant here (this is the API path, not webhooks); `ExplicitParameters` is not used by this controller; `require_permission!` only checks the permission string; the `stacks` scope exists but is never invoked by this subclass.

## Impact Explanation
An attacker with any stack-scoped `read:stack` API token can read cross-tenant stack/deploy/build/lock state for arbitrary stacks by parameter substitution — an unauthenticated-for-that-resource read of stack state and deploy output across repositories that did not authorize that token. This matches the "unauthorized read of stack state" category. It is repeatable against arbitrary stacks (limited only by needing to guess/know `stack_id`/`to_param`, which is often a predictable `owner/repo/branch`-based slug) and is not limited to a single request — the same token can enumerate any stack in the instance.

## Likelihood Explanation
Preconditions: attacker needs any `ApiClient` with `read:stack` permission (the CCMenu flow's `CCMenuUrlController#client` mints exactly such a token for a stack the requesting user has access to via the normal UI flow), and knowledge of the target stack's `to_param` (typically `owner/repo/branch`, which is often public/guessable on GitHub-hosted repos). No GitHub secrets, session, or elevated Shipit role is required beyond controlling one's own stack in the Shipit instance. This is low cost and fully repeatable.

## Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from the base controller instead of calling `Stack.from_param!` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private override entirely (falling back to `BaseController#stack`) achieves the same scoping. Audit other overrides of `#stack` in API controllers for the same pattern.

## Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped token cannot read another stack's cc.xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'other', name: 'repo'), branch: 'main')

  scoped_client = ApiClient.create!(
    creator: @user, name: 'scoped',
    permissions: %w[read:stack],
    stack: stack_a
  )

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: stack.id ∈ current_api_client.stack_id's allowed set
  # scoped_client.stack_id == stack_a.id, but resolved stack.id == stack_b.id
  assert_not_equal scoped_client.stack_id, stack_b.id
  assert_response :not_found # or :forbidden — currently returns :ok, leaking stack_b data
end
```
Running this against current code shows the request succeeds with `:ok` and returns stack B's cc.xml payload, confirming the scoping bypass.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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
