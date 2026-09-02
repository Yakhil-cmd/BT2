### Title
CCMenu API endpoint ignores an ApiClient's stack scoping, letting a token authorized for one stack read the CI/build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from the URL param instead of going through the stack-scoped lookup that every other API controller uses. This breaks the binding between "the stack an `ApiClient` is authorised for" (`ApiClient#stack_id`) and "the stack the request actually touches" (`params[:stack_id]`).

### Finding Description
`Shipit::ApiClient` supports being scoped to a single stack via its optional `stack` association [1](#0-0) . Every standard API controller enforces this scope through `Api::BaseController#stacks`/`#stack`, which restricts the queryable set of stacks to `current_api_client.stack_id` when the client is scoped: [2](#0-1) 

This is the invariant: `accessible_stacks == (client.stack_id? ? {client.stack_id} : all_stacks)`, and `stack = accessible_stacks.from_param!(params[:stack_id])` guarantees a scoped client can never touch a stack outside its grant. The test suite explicitly documents and asserts this invariant for the sibling `StacksController` ("an api client scoped to a stack will only see that one stack") [3](#0-2) .

`Api::CCMenuController`, however, overrides `stack` to bypass this entirely: [4](#0-3) 

It resolves `Stack.from_param!(params[:stack_id])` against the unscoped `Stack` relation, never consulting `current_api_client.stack_id`. The `require_permission :read, :stack` check only verifies the client's `permissions` array contains `read:stack` [5](#0-4) ; it says nothing about *which* stack the permission applies to. So any client holding `read:stack` - including one deliberately restricted to a single stack via `stack_id` - can supply an arbitrary `stack_id` route param and receive that other stack's CCMenu payload (last deploy id, status, label, time, web URL) via `show`: [6](#0-5) 

The route confirms `stack_id` is a free-form path segment supplied by the caller, not derived from the authenticated client: [7](#0-6) 

This is the direct structural analog of the `Reserve` bug: a check is performed against one identity/dimension (the client's `read:stack` permission flag, and the fact that `stack_id` *could* restrict which stack), while the action actually executed operates on a different, unchecked dimension (the arbitrary `stack_id` param) - exactly "a stack a token authorises versus a stack it touches" mismatch called out in the validation rules.

### Impact Explanation
An attacker who legitimately holds (or leaks/guesses) a stack-scoped `ApiClient` token (e.g., a token issued to a CI integration and intended to be limited to a single stack's read access) can use it to read the build/deploy status of every other stack hosted on the same Shipit instance, including stacks belonging to other repositories/teams the token holder has no authorization for. This is an authorization-boundary violation - unauthorized read of stack state across the tenant scoping the operator configured, which maps to the High-severity class "unauthenticated read of stack state ... " analog defined in the rules (the read is unauthorized relative to the token's granted scope, even though the token itself is valid).

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` token with `read:stack` permission and knowledge/guessing of another stack's `owner/name/environment` identifier (which is often predictable or discoverable, e.g. via the org's repo names). No additional secrets, sessions, or privileged access are needed beyond the token itself, and the request is a simple unauthenticated-style GET with the token in Basic Auth or the `token` query parameter (the controller explicitly supports query-string tokens for embedding in CI dashboard tools).

### Recommendation
Make `CCMenuController#stack` reuse the same scoped lookup used everywhere else in the API namespace, i.e. replace:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
with the inherited `BaseController#stack` (which uses `stacks.from_param!`, respecting `current_api_client.stack_id`), removing the local override so the scoping invariant enforced by `Api::BaseController#stacks` cannot be bypassed by any controller in this namespace.

### Proof of Concept
1. As an authorized user, create (or have an operator create) an `ApiClient` with `permissions: ['read:stack']` and `stack: StackA` (stack-scoped token), analogous to fixture `here_come_the_walrus` [8](#0-7) .
2. Confirm the scoping works as intended against a normal endpoint: `GET /api/stacks` with this token returns only `StackA` [3](#0-2) .
3. Send `GET /api/stacks/OtherOrg/StackB/production/ccmenu?token=<StackA-scoped-token>` (or via Basic Auth). Because `CCMenuController#stack` calls `Stack.from_param!` on the unscoped `Stack` relation, the request succeeds and returns `StackB`'s CCMenu XML (build status, last deploy id/time, web URL) despite the token being authorized only for `StackA`.

### Citations

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
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
