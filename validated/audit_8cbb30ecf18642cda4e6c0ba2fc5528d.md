### Title
Stack-scoped API token authorization bypass in CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` looks up the target stack directly from `Stack.from_param!(params[:stack_id])` instead of going through the stack-scoping method used everywhere else in the API. This means a token that was intended to be scoped to a single stack can be used to read the CI/deploy status of any stack in the Shipit instance.

### Finding Description
`Shipit::ApiClient` supports an optional `stack_id` scope (`belongs_to :stack, optional: true`), and `Api::BaseController` enforces that scope for every API resource lookup: [1](#0-0) 

That is, `current_api_client.stack_id?` restricts the `Stack` relation the client is allowed to resolve `params[:stack_id]` against. This is confirmed by the existing test suite, e.g. "an api client scoped to a stack will only see that one stack" for `Api::StacksController`: [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve directly against the global `Stack` relation: [3](#0-2) 

The controller only checks `require_permission :read, :stack`, which is implemented as a pure permission-bit check with no scope awareness: [4](#0-3) 

So the equality the codebase intends to enforce is:
`client.stack_id == requested_stack_id` (when `client.stack_id` is set)

but for the CCMenu endpoint the actual enforced equality collapses to:
`client.permissions.include?('read:stack')` — with no comparison against `client.stack_id` at all.

An attacker holding any token with `read:stack` permission that was issued/scoped for stack A (for example a CCMenu URL, which is designed to be embedded in third-party CI dashboards and is not treated as highly sensitive) can supply an arbitrary `stack_id` in the request and read deploy/build status for stack B, C, etc. — repositories/stacks the token was never meant to access.

### Impact Explanation
This crosses the "stack a token authorises versus a stack it touches" boundary called out as in-scope. Read access to `stack.deploys_and_rollbacks` and rendered XML (`shipit/ccmenu/project`) discloses last build status, activity, build label/time and web URL for a stack the caller has no authorization for — an unauthenticated (relative to that stack) read of stack state, which matches the High-impact category ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
Exploitation requires only possession of a valid, unrevoked token bearing `read:stack` permission — no elevated privileges needed to pivot beyond the single stack the token was meant for. Such tokens are handed out fairly liberally via the CCMenu URL flow (`CCMenuUrlController`) precisely because they were assumed to be low-risk/single-stack. The bug is a straightforward method override that skips the shared scoping helper, so it is triggered by simply passing a different `stack_id` in the query string; no race condition, timing, or unusual state is required.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the shared, scope-aware helper instead of hitting `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
reusing `Api::BaseController#stacks`, so a stack-scoped `ApiClient` cannot resolve stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. Admin creates (or the app auto-creates via `CCMenuUrlController#client`) an `ApiClient` with `permissions: ['read:stack']`; assume it is (or could be) scoped with `stack_id` pointing to `stack-A` (this scoping mechanism exists and is enforced for `Api::StacksController`/other API resources).
2. Obtain that client's `authentication_token` (e.g., from a shared/embedded CCMenu URL, which is designed to be pasted into third-party CI aggregator tools).
3. Send: `GET /api/ccmenu/stack-B?token=<token-scoped-to-stack-A>` (or any other `stack_id` in the Shipit instance).
4. `authenticate_api_client` succeeds (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the client has `read:stack`, and `stack` resolves `stack-B` via `Stack.from_param!` with no scope check — returning `stack-B`'s deploy status XML, which the token holder was never authorized to see.

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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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
