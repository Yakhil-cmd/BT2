### Title
CCMenu token scoped to stack B reads stack A's status — `Api::CCMenuController#stack` bypasses `current_api_client.stack_id` scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` enforces that a stack-scoped `ApiClient` can only touch the stack it was minted for by routing all stack lookups through the `#stacks` method, which filters by `current_api_client.stack_id`. `Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting `#stacks`/`current_api_client.stack_id`, so any valid CCMenu token can be replayed against an arbitrary `stack_id` to read that other stack's build/deploy status.

### Finding Description
The intended binding is: `stack.id == current_api_client.stack_id` whenever `current_api_client.stack_id?` is true. This is implemented in `Api::BaseController#stacks`/`#stack`: [1](#0-0) 

Every other API controller that reads a stack goes through this scoped helper, e.g. `Api::StacksController#stack`: [2](#0-1) 

`Api::CCMenuController`, however, redefines `#stack` to bypass the scope entirely and also overrides `authenticate_api_client` to accept a `?token=` query param instead of Basic Auth: [3](#0-2) 

`require_permission :read, :stack` only checks that the client's `permissions` array contains the string `"read:stack"` via `ApiClient#check_permissions!`; it never checks `stack_id`: [4](#0-3) 

`ApiClient` itself supports being scoped to a single stack (`belongs_to :stack, optional: true`), and `ApiClient.authenticate` only verifies the signed id, returning whatever client that id maps to, with whatever `stack_id` it has: [5](#0-4) 

Attacker flow: obtain (phish/share) a legitimate CCMenu URL such as `GET /stacks/companyB/prod/ccmenu.xml?token=<t>` where `t` verifies to an `ApiClient` whose `stack_id` is stack B's id. Replay the same token with `stack_id` swapped to stack A: `GET /stacks/companyA/prod/ccmenu.xml?token=<t>`. `authenticate_api_client` sets `@current_api_client` to the valid client (scoped to B). `require_permission :read, :stack` passes because the client has `read:stack` in its permissions, irrespective of which stack is requested. `#show` calls `#stack`, which resolves `Stack.from_param!(params[:stack_id])` for stack A directly — the `current_api_client.stack_id` binding to B is never checked — and stack A's deploy/build status XML is rendered to the attacker.

None of the documented guards intervene: `verify_signature`/webhook checks are irrelevant here; `ExplicitParameters` isn't used by this controller; `force_github_authentication` doesn't apply to the API namespace; `User#authorized?`/`require_permission!` only checks the permission string, not stack scope; and the `stacks` scope that would have prevented this is simply not called by `CCMenuController#stack`.

### Impact Explanation
An attacker holding any CCMenu token minted for one stack (even a low-privilege, single-repo CCMenu client generated automatically by `CCMenuUrlController#fetch`) can enumerate and read any other stack's CI/deploy status (`activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) by swapping the `stack_id` path segment, without ever needing credentials for that other stack. This is repeatable against arbitrary stacks/tenants sharing the same Shipit instance and matches the High-severity category "unauthenticated read of stack state ... or deploy output" since the requester is not authorized for the target stack at all.

### Likelihood Explanation
The only precondition is possession of any one valid CCMenu token (these are routinely embedded in plaintext CI dashboard URLs, e.g. CCTray/CCMenu client configs, and are generated without any stack-scope hardening by `CCMenuUrlController#fetch`). No secrets, sessions, or GitHub credentials are required, and the attack is a single unauthenticated GET request with a modified path parameter — trivially repeatable.

### Recommendation
Remove the `#stack` override in `Api::CCMenuController` (or reimplement it via `stacks.from_param!(params[:stack_id])`) so it goes through the same `current_api_client.stack_id`-scoped lookup as every other API controller, ensuring `Stack::NotFound`/403 is raised when the token's `stack_id` doesn't match the requested stack.

### Proof of Concept
In `test/controllers/api/ccmenu_controller_test.rb` (minitest, `ActionController::TestCase`):
```ruby
test "a token scoped to stack B cannot read stack A" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'other', name: 'repo'), branch: 'main')
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'scoped', permissions: %w[read:stack], stack: stack_b)

  get :show, params: { stack_id: stack_a.to_param, token: client.authentication_token }

  # Binding under test: stack.id == current_api_client.stack_id
  assert_not_equal stack_a.id, client.stack_id
  assert_response :not_found # or :forbidden — currently fails: renders stack_a's XML with :ok
end
```
This demonstrates that `stack.id` (stack A) diverges from `current_api_client.stack_id` (stack B) while the request still succeeds with `200 OK` and renders stack A's data, confirming the broken binding.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/api_client.rb (L7-27)
```ruby
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

    class << self
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
