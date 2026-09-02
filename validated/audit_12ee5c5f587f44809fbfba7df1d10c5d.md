### Title
Cross-tenant CCMenu status leak via unscoped `stack` override bypassing per-client `stack_id` restriction - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the `stack` accessor to `Stack.from_param!(params[:stack_id])`, completely bypassing the `stack_id`-scoping performed by `BaseController#stacks`/`#stack`. Any holder of a valid `ApiClient` token — even one that is only supposed to be scoped to a single stack — can request `show` for any other stack's `stack_id` and receive its deploy status.

### Finding Description
The intended binding is: for a scoped client, `current_api_client.stack_id == stack.id` must hold before `stack.deploys_and_rollbacks` is read. `BaseController` enforces this via [1](#0-0) 
where `stacks` is filtered by `current_api_client.stack_id` when the client has one, and `stack` is derived from that filtered scope with `stacks.from_param!`.

`CCMenuController` redefines `stack` independently: [2](#0-1) 
using `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, never referencing `current_api_client.stack_id`.

The only authorization check applied is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(:read, :stack)`: [3](#0-2) 
This only checks that `"read:stack"` is in the client's `permissions` array — it never compares the requested stack's id to `current_api_client.stack_id`. There is no other guard tying the requested `stack_id` param to the authenticated client's assigned stack.

Exploit flow: an attacker who obtains any valid CCMenu token (via a leaked/pasted CCMenu URL containing `token=...`, since the controller's own `authenticate_api_client` accepts the token from `params[:token]`) can call:
```
GET /stacks/:owner/:repo_a/:env_a.xml?token=<leaked-token-scoped-to-stack-A>
```
but instead substitute an arbitrary `stack_id` for stack B in the URL. Because `stack` never filters by `current_api_client.stack_id`, `Stack.from_param!` resolves stack B directly, `require_permission!` passes (it only checks the generic `read:stack` permission string), and `stack.deploys_and_rollbacks.last` returns stack B's real deploy history, rendered in the CCMenu XML response.

### Impact Explanation
This is an unauthenticated-for-that-resource, cross-tenant read of deploy status: a token issued/scoped for stack A discloses stack B's latest deploy id, status (success/failure), timestamps and lock state. This matches the High severity category "unauthenticated read of stack state" since any legitimately obtained-but-narrowly-scoped token becomes usable against every stack in the installation, not just its assigned one — repeatable for arbitrary `stack_id` values with no rate limiting beyond normal HTTP access.

### Likelihood Explanation
Preconditions: attacker needs any valid `ApiClient` token (any scope), which is intentionally embedded in plaintext CCMenu URLs meant to be pasted into CI dashboards/browsers — a realistic leak vector documented by the feature itself. No GitHub secrets, no session, and no admin/maintainer role are required. The attack is a single GET request with a substituted `stack_id`/path segment; cost is trivial and fully repeatable against every stack on the instance.

### Recommendation
Make `CCMenuController#stack` use the scoped `stacks` accessor from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so that a client with a non-nil `stack_id` cannot resolve any stack other than its own, consistent with every other API controller.

### Proof of Concept
```ruby
test "a token scoped to stack A cannot read stack B's status via ccmenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "scoped-client",
    stack_id: stack_a.id,
    permissions: %w[read:stack]
  )

  # Binding under test: current_api_client.stack_id == stack.id must hold
  assert_equal stack_a.id, client.stack_id
  refute_equal client.stack_id, stack_b.id

  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

  # Expect this to be rejected (403/404); currently it renders stack_b's data
  assert_response :not_found # or :forbidden — fix should make this pass
  # Before fix: assert_response :ok and payload discloses stack_b's real deploy/lastBuildStatus
end
```
This demonstrates that `client.stack_id` (bound to stack A) and the resolved `stack.id` (stack B) diverge, yet the controller still renders stack B's `deploys_and_rollbacks`, confirming the broken binding.

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
