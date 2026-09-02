Confirmed: this test even demonstrates the bug — `test "stacks with no deploys render correctly"` creates an arbitrary new stack (`Repository.new(owner: "foo", name: "bar")`) unrelated to `@client`'s scoped stack, and fetches it successfully with the `@client` token (`here_come_the_walrus`/`spy`), proving `CCMenuController#stack` ignores the token's `stack_id` scope.

### Title
Stack-scoped API token can read any stack's build status via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly via `Stack.from_param!(params[:stack_id])` instead of using the inherited, properly-scoped `BaseController#stack`/`#stacks` helpers. As a result, an `ApiClient` token that was created scoped to a single stack (`stack_id` set) can be used to read the build/deploy status of **any** stack in the installation, not just the one it was authorized for.

### Finding Description
`ApiClient` tokens can optionally be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0)  . The generic API `BaseController` enforces this scope by deriving the visible stack set from `current_api_client.stack_id`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

However, `CCMenuController` overrides `#stack` and bypasses this scoping entirely, resolving the parameter against the global `Stack` relation:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

The controller only checks the token's coarse-grained `read:stack` permission (`require_permission :read, :stack`) [4](#0-3)  via `ApiClient#check_permissions!`, which validates the permission *name* only and has no notion of which stack it applies to: [5](#0-4) . The `stack_id` binding that the token was created with is never consulted in this controller.

This breaks the intended equality: "the stack a token is authorized for" should equal "the stack the request actually touches." Any client with a valid `read:stack`-permitted token — even one explicitly scoped to a single, low-sensitivity stack — can enumerate/query `show` for every other stack by simply changing the `stack_id` request parameter, disclosing deploy status, lock state, and last build info for stacks it has no authorization over.

### Impact Explanation
This is an authorization-scope bypass: it grants unauthenticated-for-that-resource read access to stack state (lock status, latest deploy/rollback outcome) across the entire Shipit installation using a token meant to be confined to one stack. This matches the "High" impact class of unauthorized read of stack state via a boundary crossing between what the token authorizes and what it can actually touch.

### Likelihood Explanation
Trivial to exploit: any holder of a stack-scoped `ApiClient` token (a routine, lower-privilege credential intentionally restricted to a single stack) needs only to modify the `stack_id` URL parameter of the `GET /api/:stack_id/cc.xml`-style endpoint to read information about unrelated stacks. No additional privileges, timing, or race conditions are required.

### Recommendation
Remove the `CCMenuController#stack` override (or make it delegate to the inherited `stacks`/`stack` helpers from `BaseController`) so that stack resolution is scoped by `current_api_client.stack_id` the same way it is everywhere else in the API:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to `StackA.id` — this is the standard pattern used for CI status badges/tokens meant to be handed out per-project, as documented in `test/fixtures/shipit/api_clients.yml` (`here_come_the_walrus`, scoped to `shipit` stack) [6](#0-5) .
2. Authenticate with this token (`Authorization: Basic <token>` or `?token=<token>`) as done in `authenticate_api_client` for `CCMenuController` [7](#0-6) .
3. Send `GET /api/:other_stack_id/cc.xml?token=<token>` where `other_stack_id` references any other stack in the installation (`StackB`, belonging to a different repository/team).
4. Observe that the response is `200 OK` and renders `StackB`'s deploy/build status, even though the token's `stack_id` is `StackA.id`. This is directly demonstrated by the existing test that creates a brand-new, unrelated `Stack` and successfully reads its status with the same client token [8](#0-7) .

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L47-51)
```ruby
      test "stacks with no deploys render correctly" do
        stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
        get :show, params: { stack_id: stack.to_param }
        assert_payload 'lastBuildStatus', 'Success'
      end
```
