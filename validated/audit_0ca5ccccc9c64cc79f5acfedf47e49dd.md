### Title
Stack-scoped `ApiClient` tokens can read any stack's build/deploy status via `Api::CCMenuController#stack` bypassing the client's `stack_id` scope - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via its `stack_id` column, and `Api::BaseController` enforces this scope through the `stacks`/`stack` helper methods used by every other stack-nested API endpoint. `Api::CCMenuController` overrides `stack` to bypass this scoping entirely, so a token that is only supposed to authorize `read:stack` for one specific stack can be used to fetch build/deploy status for **any** stack in the installation.

### Finding Description
`ApiClient` records can carry a `stack_id`, restricting the client to a single stack: `here_come_the_walrus` fixture demonstrates this pattern (`stack: shipit`, `permissions: ['read:stack']`) [1](#0-0) .

`Api::BaseController` is where this scope is meant to be enforced for every controller that inherits from it — `stacks` returns only the client's own stack when `stack_id?` is true, and `stack` resolves `params[:stack_id]` against that restricted relation: [2](#0-1) 

This is the trust binding: **the stack the token authorizes (`ApiClient#stack_id`) must equal the stack the request touches (`params[:stack_id]` resolved through `stacks`)**. `Api::StacksController` and other nested API resources rely on this inherited `stack` method, and the test suite explicitly documents the expectation — "an api client scoped to a stack will only see that one stack" [3](#0-2) .

`Api::CCMenuController`, however, redefines `stack` to resolve the parameter against **all** stacks, discarding the `stacks` scoping from `BaseController`: [4](#0-3) 

The `require_permission :read, :stack` before_action only checks that the string `"read:stack"` is in the client's `permissions` array via `ApiClient#check_permissions!` [5](#0-4)  — it never checks `stack_id` against the requested stack. Because `CCMenuController#stack` never calls the inherited `stacks` helper, the `stack_id?` restriction is silently skipped.

Before the flaw: `stack_id token authorizes == stack_id request touches` (enforced in every other nested API controller via `BaseController#stacks`).
After: for `Api::CCMenuController#show`, `stack_id token authorizes != stack_id request touches` is permitted — any `stack_id` in the route param is resolved regardless of the token's own `stack_id`.

### Impact Explanation
An attacker who legitimately holds (or otherwise obtains, e.g. from a CCMenu URL shared for one project) a `read:stack`-scoped token intended for a single stack can call `GET /api/stacks/<any-owner>/<any-repo>/<any-env>/ccmenu` for a different stack they were never authorized to see, and receive build/deploy status: `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and lock state [6](#0-5) . This is an unauthenticated (relative to the intended scope) read of stack state and deploy output across repositories, matching the High-severity "unauthenticated read of stack state, task streams or deploy output" category.

### Likelihood Explanation
Stack-scoped tokens are a first-class, documented feature of `ApiClient` (`belongs_to :stack, optional: true`), and the CCMenu endpoint's `stack` override is the only nested-stack API controller found that fails to reuse `BaseController#stacks`. Any holder of a stack-scoped `read:stack` token — a legitimate but lower-privilege integration (e.g., a CI widget) — can trivially trigger this by varying the `stack_id` path segment. No other authorization boundary needs to be crossed since `CCMenuController` also supports the same signed token via a `token` query parameter [7](#0-6) .

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it to delegate through the inherited `stacks` scope), e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that stack-scoped tokens are restricted to their assigned stack the same way as all other nested API resources.

### Proof of Concept
1. Admin creates (e.g. via console/Rails admin) `ApiClient` `A` with `stack_id` pointing to `stack-1`, `permissions: ['read:stack']`.
2. Attacker holding token `A` calls:
   `GET /api/stacks/other-owner/other-repo/production/ccmenu?token=<A.authentication_token>`
3. `Api::CCMenuController#stack` resolves `params[:stack_id]` via `Stack.from_param!` against **all** stacks (not `stacks.from_param!`), so `stack-2` (a different, unauthorized stack) is returned.
4. `require_permission :read, :stack` passes because it only checks the string permission, not `stack_id` equality — the response leaks `stack-2`'s deploy/build status even though token `A` was only ever meant to authorize `stack-1`.

### Citations

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-45)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end
```
