### Title
CCMenuController bypasses per-stack ApiClient scoping, allowing cross-stack disclosure of stack state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` restricts an `ApiClient` that is bound to a specific `stack` (`belongs_to :stack, optional: true`) to only ever resolve stacks through the `stacks`/`stack` helpers, which intersect the request with `current_api_client.stack_id`. `Shipit::Api::CCMenuController` overrides `stack` and resolves the stack directly from `params[:stack_id]` via `Stack.from_param!`, completely skipping that scoping. The result is that an `ApiClient` token that is only supposed to authorize `read:stack` for one specific stack can be replayed with a different `stack_id` to read the CCMenu status of any other stack.

### Finding Description
`ApiClient` supports being scoped to a single stack: [1](#0-0) 

The base controller enforces that scoping generically for every other API endpoint: [2](#0-1) 

This is confirmed by test coverage showing a stack-scoped client ("here_come_the_walrus", scoped to the `shipit` stack) is restricted to seeing only its own stack via `stacks`: [3](#0-2) [4](#0-3) 

However, `CCMenuController` defines its own `stack` method that ignores the `current_api_client.stack_id` restriction entirely, resolving directly from the global `Stack` collection using only the request parameter: [5](#0-4) 

The only authorization check performed before `show` is a generic textual permission check (`read:stack`), which does not take the specific stack into account: [6](#0-5) 

This breaks the binding: `current_api_client.stack_id` (the stack the token authorizes) ≠ `params[:stack_id]` (the stack the action actually touches). Every other API controller derives the effective stack from `current_api_client`-intersected `stacks`, so this scoping gap is specific to `CCMenuController`.

### Impact Explanation
An `ApiClient` token that was deliberately restricted to a single stack (e.g., minted by `Shipit::CCMenuUrlController#client`, or configured by an admin via `belongs_to :stack`) can be used to read the CCMenu XML status — including stack name, activity, last build status/label, and web URL — of any other stack in the Shipit instance, regardless of the intended per-stack restriction. This is an authorization-boundary bypass: it defeats the confidentiality guarantee that a stack-scoped API token cannot be used to enumerate/observe the deploy state of unrelated stacks, which qualifies as unauthorized read of stack state across the per-token authorization boundary.

### Likelihood Explanation
Exploitation requires only possession of a legitimately-scoped `read:stack` API token (no privileged access or webhook secret needed) and knowledge/guessing of another stack's identifier (`owner/repo/environment`), which is often predictable or discoverable. The `token` GET param authentication path is explicitly supported (`authenticate_api_client` accepts `params[:token]`), making this trivially reachable over an unauthenticated HTTP GET once a scoped token is obtained.

### Recommendation
Change `CCMenuController#stack` to resolve through the same `stacks` scoping used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient` cannot resolve stacks outside of its authorized `stack_id`.

### Proof of Concept
1. Admin creates (or the system auto-creates via `CCMenuUrlController`) an `ApiClient` scoped to `stack_id` = Stack A, with `permissions: ['read:stack']`.
2. Attacker obtains this token (e.g., it is designed to be embedded in a CCMenu URL query string: `app/controllers/shipit/ccmenu_url_controller.rb`).
3. Attacker issues `GET /api/other_owner/other_repo/other_env/ccmenu.xml?token=<stack-A-scoped-token>`.
4. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly (ignoring `current_api_client.stack_id`), and `check_permissions!(:read, :stack)` only checks the textual permission list, so the request succeeds and returns Stack B's build/deploy status, even though the token was only supposed to authorize Stack A.

### Citations

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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
