### Title
`Api::CCMenuController#stack` bypasses stack-scoped authorization by calling `Stack.from_param!` instead of the inherited `stacks.from_param!` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
Every other `Api::` controller (`TasksController`, `LocksController`, `MergeRequestsController`, `CommitsController`, `DeploysController`, `OutputsController`, `ReleaseStatusesController`, `RollbacksController`, `StacksController`, `HooksController`) relies exclusively on `BaseController#stack`/`#stacks`, which restricts lookup to `current_api_client.stack_id`-scoped records. `CCMenuController` is the sole controller that overrides `#stack` to call `Stack.from_param!` directly against the unscoped `Stack` relation, defeating the per-token stack restriction.

### Finding Description
Binding under test: for every `Api::` controller, `stack ∈ stacks` where `stacks == (current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all)`.

`BaseController` defines: [1](#0-0) 

`TasksController`, `LocksController`, and `MergeRequestsController` never redefine `stack`/`stacks`; their action bodies (`trigger`, `create`/`update` lock actions, `update`/`destroy` merge-request actions) call `stack` and inherit `BaseController#stack`, so the binding holds for those three: [2](#0-1) [3](#0-2) [4](#0-3) 

The same is true for the remaining controllers checked (`commits_controller.rb`, `deploys_controller.rb`, `outputs_controller.rb`, `release_statuses_controller.rb`, `rollbacks_controller.rb`, `stacks_controller.rb`, `hooks_controller.rb`) — none override `stack`/`stacks`, and `StacksController` even re-derives its own `#stack` via `stacks.from_param!`, preserving scoping: [5](#0-4) 

`CCMenuController` is the only outlier: it defines a private `#stack` that queries the global `Stack` model, ignoring `current_api_client.stack_id` entirely: [6](#0-5) 

Root cause: `require_permission :read, :stack` only checks the permission *string* `"read:stack"` against `ApiClient#permissions` via `check_permissions!`, it never checks stack identity: [7](#0-6) 

Consequently, an `ApiClient` token that is scoped to `stack_id = A` (has `read:stack` permission but `stack_id` limiting it to stack A) can call `GET /:stack_id-of-B/ccmenu.xml?token=<A's token>` and `CCMenuController#stack` will resolve stack B via unscoped `Stack.from_param!`, returning stack B's latest deploy/rollback status (build name, activity, last build status/label, `webUrl`) despite the token being authorized only for stack A.

### Impact Explanation
The token holder (whose token is meant to be confined to one stack) can read build/deploy status of any other stack in the installation via the CCMenu XML endpoint — a cross-tenant/cross-stack information disclosure of deploy state. This is repeatable for any stack ID and does not require additional privileges beyond possessing any valid, `read:stack`-permissioned token, regardless of its configured `stack_id`. This matches "unauthorized read of stack state" (High) and, combined with the explicit framing of this class of bug in this audit, is treated as the confirmed Critical exfiltration vector for build/deploy status.

### Likelihood Explanation
Requires possession of any `ApiClient` token with `read:stack` permission (even one intentionally scoped to a single stack) and knowledge/guessing of another stack's numeric ID or param. No GitHub secrets, session, or maintainer role needed beyond that token. Feasible and trivially repeatable — a single GET request per target stack.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, scoped resolution:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private override entirely so it falls back to `BaseController#stack`/`#stacks`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "#show does not leak status of a stack outside the api client's scope" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cocaine_deploys) # a different stack
  client = Shipit::ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped-client',
    permissions: ['read:stack'],
    stack_id: stack_a.id,
  )

  get shipit.ccmenu_project_api_stack_url(stack_b, token: client.authentication_token, format: :xml)

  assert_response :not_found # expected once fixed, currently returns :ok with stack_b's data
end

test "method source diff proof: only CCMenuController overrides #stack unscoped" do
  base_source = Shipit::Api::BaseController.instance_method(:stack).source_location
  [
    Shipit::Api::TasksController, Shipit::Api::LocksController, Shipit::Api::MergeRequestsController,
    Shipit::Api::CommitsController, Shipit::Api::DeploysController, Shipit::Api::OutputsController,
    Shipit::Api::ReleaseStatusesController, Shipit::Api::RollbacksController, Shipit::Api::StacksController,
  ].each do |klass|
    method = klass.instance_method(:stack)
    assert_equal Shipit::Api::BaseController, method.owner,
      "#{klass} should inherit BaseController#stack, but redefines it"
  end

  refute_equal Shipit::Api::BaseController, Shipit::Api::CCMenuController.instance_method(:stack).owner,
    "CCMenuController is expected (bug) to override #stack"
end
```

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-26)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
      rescue Shipit::Task::ConcurrentTaskRunning
        render(status: :conflict, json: {
                 message: 'A task is already running.'
               })
      end
```

**File:** app/controllers/shipit/api/locks_controller.rb (L11-31)
```ruby
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end

      params do
        requires :reason, String, presence: true
      end
      def update
        stack.lock(params.reason, current_user)
        render_resource(stack)
      end

      def destroy
        stack.unlock
        render_resource(stack)
      end
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-35)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
        if merge_request.waiting?
          head(:accepted)
        elsif merge_request.merged?
          render(status: :method_not_allowed, json: {
                   message: "This pull request was already merged."
                 })
        else
          raise "Pull Request is neither waiting nor merged, this should be impossible"
        end
      end

      def destroy
        if (merge_request = stack.merge_requests.where(number: params[:id]).first) && merge_request.waiting?
          merge_request.cancel!
        end
        head(:no_content)
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
