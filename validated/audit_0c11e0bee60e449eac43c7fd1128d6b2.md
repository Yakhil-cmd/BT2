### Title
Scoped API token can read CCMenu status/deploy output for stacks it is not authorized for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor to load the requested stack directly from `Stack.from_param!`, bypassing the stack-scoping enforced by `Shipit::Api::BaseController#stacks`/`#stack`. An `ApiClient` token that is restricted to a single stack via `stack_id` can be replayed against any other stack's `/api/stacks/:stack_id/ccmenu` endpoint to read that stack's deploy/build status, breaking the binding "stack a token authorises" == "stack it touches".

### Finding Description
`Shipit::ApiClient` supports scoping a token to a single stack via the `stack_id` column: [1](#0-0) .

`BaseController` enforces this scope for every normal API endpoint by filtering the queryable stacks through `current_api_client.stack_id?`: [2](#0-1) 

This is the binding that guarantees `stack a token authorises == stack it touches` across the API namespace (confirmed by the fixture-driven test "an api client scoped to a stack will only see that one stack") [3](#0-2) .

`CCMenuController`, however, redefines `stack` to bypass this scoping entirely, loading any stack directly by its param instead of going through the scoped `stacks` relation: [4](#0-3) 

The only check performed before rendering is a permission-string check (`read:stack`) via `require_permission`, which validates the operation/scope pair but never validates that the requested `stack_id` matches the token's `stack_id`: [5](#0-4) 

As a result, holding a token scoped to Stack A (with `read:stack` permission) is sufficient to query `GET /api/stacks/<Stack-B-full-name>/ccmenu` and receive Stack B's CCMenu XML, including latest deploy/build status: [6](#0-5) 

### Impact Explanation
This breaks the "stack a token authorises vs stack it touches" binding named in the audit scope. It grants a stack-scoped credential unauthorized read access to another repository/stack's deploy state (last build status, label, and time) that the token owner was never granted access to. This matches the High-impact category "unauthenticated read of stack state ... or deploy output" (here, effectively unauthorized read across the token's own authorization boundary), since the `stack_id` scoping restriction — the only mechanism limiting this class of token to one stack — is not enforced on this endpoint.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a supported, tested first-class feature — e.g. exposed for CCMenu integrations via `stack_id`-bound clients) to third parties or CI systems with limited trust. Any holder of such a token can trivially enumerate/target other stacks by simply changing the `stack_id` path segment.

### Recommendation
Remove the `stack` override in `CCMenuController` and let it fall back to `BaseController#stack`, which is derived from the scoped `stacks` relation (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`), so a stack-scoped token cannot resolve stacks outside its authorized `stack_id`.

### Proof of Concept
1. Admin issues an `ApiClient` token scoped to Stack A: `ApiClient.create!(creator:, name: "ccmenu", permissions: ["read:stack"], stack_id: StackA.id)`.
2. Using that token's `authentication_token`, request `GET /api/stacks/<StackB-owner>/<StackB-repo>/<StackB-env>/ccmenu` (or via `?token=` on the equivalent XML endpoint).
3. `authenticate_api_client` succeeds (valid token, `read:stack` permission present) and `CCMenuController#stack` resolves Stack B directly via `Stack.from_param!`, ignoring the client's `stack_id` scope — returning Stack B's CCMenu status even though the token is only authorized for Stack A.

### Citations

**File:** app/models/shipit/api_client.rb (L4-12)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
