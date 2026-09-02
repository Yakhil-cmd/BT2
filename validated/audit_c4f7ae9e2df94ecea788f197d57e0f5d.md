### Title
API client scoped to a single stack can read CI/deploy status of any stack via CCMenu - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` tokens can be scoped to a single stack via `stack_id` [1](#0-0) , and `Api::BaseController` enforces that scoping by restricting the queryable stacks to `Stack.where(id: current_api_client.stack_id)` whenever a `stack_id` is set on the client [2](#0-1) . `Api::CCMenuController`, however, overrides the `stack` resolution to look the stack up directly from `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks` scoping helper [3](#0-2) .

### Finding Description
`ApiClient#check_permissions!` only validates that the client holds the `read:stack` permission string; it never validates which stack instance the permission applies to [4](#0-3) . The per-stack restriction is instead enforced entirely at the controller layer through the `stacks`/`stack` helper methods in `BaseController` [2](#0-1) , which every other resource controller (e.g. `DeploysController`, `RollbacksController`, `TasksController`, `MergeRequestsController`) relies on to translate `params[:stack_id]` into a `Stack` object that is guaranteed to belong to the client's authorized scope.

`CCMenuController` redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly, ignoring `current_api_client.stack_id` entirely [5](#0-4) . This breaks the binding "a stack a token authorizes vs. a stack it touches": the token is only authorized (by its `stack_id` column) for one specific stack, but the controller lets it act on (read) any stack in the system by supplying a different `stack_id` param.

### Impact Explanation
This produces an unauthorized read of stack state: an `ApiClient` deliberately scoped to a single, presumably less-sensitive stack can retrieve CCTray XML (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for any other stack in the deployment, including private/production stacks it was never granted access to [6](#0-5) . This matches the "High - unauthenticated read of stack state" impact bucket, since the token holder is not authenticated/authorized for the target stack yet can still read its deploy/build status.

### Likelihood Explanation
No front-running or privileged access is required beyond possessing any valid `ApiClient` token that has the `read:stack` permission and a `stack_id` restriction — exactly the scenario the `stack_id` scoping feature is meant to prevent from over-reaching. The only "attacker" action needed is passing a different `stack_id` query parameter, which is trivial and requires no additional credentials.

### Recommendation
Change `CCMenuController#stack` to resolve through the inherited `stacks` scope (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so stack-scoped API clients cannot query stacks outside their authorized `stack_id`.

### Proof of Concept
1. Create `ApiClient` A with `permissions: ['read:stack']` and `stack_id` set to `stack_low_sensitivity.id`.
2. Using A's `authentication_token`, call `GET /api/cc/:stack_id/cc.xml` (CCMenu `show` route) with `stack_id` set to a *different*, unrelated stack's param (e.g. a production stack A was never assigned to).
3. Observe the controller resolves `stack` via `Stack.from_param!(params[:stack_id])` [5](#0-4) , bypassing the `current_api_client.stack_id` restriction enforced elsewhere [2](#0-1) , and returns the target stack's build/deploy status XML despite A's token being scoped only to the low-sensitivity stack.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-39)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end
```
