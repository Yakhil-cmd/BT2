### Title
Stack-scoped `write:stack` API tokens can create arbitrary stacks outside their authorized scope - ([File: app/controllers/shipit/api/stacks_controller.rb])

### Summary
`ApiClient` records can be scoped to a single `stack_id`, which is meant to bind everything that token is authorized to touch to that one stack. [1](#0-0)  This binding is enforced for read/update/destroy/refresh via the `stacks`/`stack` helpers in `Api::BaseController` and `Api::StacksController`, but the `create` action never consults it, letting a stack-scoped token with `write:stack` permission create brand-new stacks for any repository.

### Finding Description
`Api::BaseController#stacks` computes the token's authorized set of stacks as `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `Api::StacksController#stack` (`stacks.from_param!(params[:id])`) is used by `show`, `update`, `destroy`, and `refresh` to enforce that scope. [2](#0-1) [3](#0-2) [4](#0-3) 

The `create` action, however, bypasses this entirely:
```ruby
def create
  stack = Stack.new(create_params)
  stack.repository = repository
  stack.save
  render_resource(stack)
end
``` [5](#0-4) 

It only checks `require_permission :write, :stack` at the class level (`ApiClient#check_permissions!` merely checks membership in the client's `permissions` array, with no reference to `stack_id`). [6](#0-5) [7](#0-6)  The repository is derived directly from attacker-supplied `repo_owner`/`repo_name` params via `Repository.find_or_create_by`, with no relation to the token's bound `stack_id`. [8](#0-7) 

The binding that is broken (as an equality) is:
`stack a token authorizes (current_api_client.stack_id)` ≠ `stack/repository the create action actually writes (Stack.new(create_params) with an arbitrary repository)`.

Before the attacker's request: a stack-scoped token (e.g. `here_come_the_walrus`, scoped to stack `shipit`, fixture shows `stack: shipit`) [9](#0-8)  is intended to only read/write that one stack. If such a token is also granted `write:stack` (a realistic configuration for automation that needs to update its own stack's settings), after the attacker's request it can call `POST /api/stacks` with `repo_owner`/`repo_name` for a completely different repository and successfully create a new `Stack` record tied to that unrelated repository — something `index`/`show`/`update`/`destroy` on that token would otherwise never allow it to see or touch.

### Impact Explanation
This is a cross-repository write: a token deliberately restricted (by an administrator) to operate on a single stack can create deploy targets (with `branch`, `environment`, `deploy_url`, `continuous_deployment` settings) for repositories it has no legitimate authorization over. A newly created stack immediately begins syncing commits/CI status from GitHub and, if `continuous_deployment` is set, can trigger deploys, matching the "cross-repository writes" / "unauthorized deploy" Critical-impact category defined in scope.

### Likelihood Explanation
Exploitation requires only possession of a stack-scoped `ApiClient` token that also carries the generic `write:stack` permission — a plausible and unremarkable configuration, since `stack_id` scoping and the `PERMISSIONS` list are independent, orthogonal concepts in the `ApiClient` model (nothing in `check_permissions!` or the `create_params`/`repository` helpers references `stack_id`). No other privilege beyond an already-issued API token is needed, and the existing test suite only verifies permission checks and full-scope creation, not that a stack-scoped token is restricted from creating unrelated stacks. [10](#0-9) 

### Recommendation
In `Api::StacksController#create`, reject the request (or force `stack.repository`/target to the client's bound stack) when `current_api_client.stack_id?` is true, since a stack-scoped token has no legitimate need to create additional stacks. At minimum, add an explicit check such as `raise ApiClient::InsufficientPermission if current_api_client.stack_id?` before creating a new `Stack`, mirroring the scoping already applied by the `stacks` helper for the other actions.

### Proof of Concept
1. Admin issues an `ApiClient` scoped to `stack_id` = stack A, with permissions including `write:stack` (intended only to let an automation deploy/update stack A).
2. Using that token's Basic-Auth credentials, call:
   ```
   POST /api/stacks
   repo_owner=some-other-org
   repo_name=unrelated-repo
   environment=production
   branch=main
   continuous_deployment=true
   ```
3. `Api::StacksController#create` runs `Stack.new(create_params)` / `stack.repository = repository` without consulting `current_api_client.stack_id`, and returns `201`/`200` with the newly created stack for `unrelated-repo` — a repository the token was never scoped to via `stack_id`, and which the same token cannot `index`/`show`/`update` afterward (proving the scope was bypassed only for creation).

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L6-7)
```ruby
      require_permission :read, :stack, only: %i[index show]
      require_permission :write, :stack, only: %i[create update destroy]
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L36-41)
```ruby
      def create
        stack = Stack.new(create_params)
        stack.repository = repository
        stack.save
        render_resource(stack)
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L60-79)
```ruby
      def show
        render_resource(stack)
      end

      def destroy
        stack.schedule_for_destroy!
        head(:accepted)
      end

      def refresh
        RefreshStatusesJob.perform_later(stack_id: stack.id)
        RefreshCheckRunsJob.perform_later(stack_id: stack.id)
        # force_spec_cache: explicit refreshes always recompute the cached deploy
        # spec, even when the head hasn't moved: refreshing is how a stale or
        # broken cached spec is fixed. Threading it through the sync job (rather
        # than enqueuing CacheDeploySpecJob directly) guarantees the spec is
        # computed from the post-sync head.
        GithubSyncJob.perform_later(stack_id: stack.id, force_spec_cache: true)
        render_resource(stack, status: :accepted)
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L111-113)
```ruby
      def repository
        @repository ||= Repository.find_or_create_by(owner: repo_owner, name: repo_name)
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

**File:** test/controllers/api/stacks_controller_test.rb (L33-40)
```ruby
      test "#create creates a stack and renders it back" do
        assert_difference -> { Stack.count } do
          post :create, params: { repo_name: 'rails', repo_owner: 'rails', environment: 'staging', branch: 'staging' }
        end

        assert_response :ok
        assert_json 'id', Stack.last.id
      end
```
