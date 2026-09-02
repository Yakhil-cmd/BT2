### Title
`ApiClient` scoped to stack A can create a new `Stack` for an unrelated repository B via `POST /api/stacks` - ([File: app/controllers/shipit/api/stacks_controller.rb])

### Summary
`StacksController#create` builds a brand new `Stack` from `repo_owner`/`repo_name` params and only checks the `write:stack` permission flag, never comparing the target repository/stack against `current_api_client.stack_id`. Every other action (`show`, `update`, `destroy`, `refresh`) is scoped through the `stacks` helper (`Stack.where(id: current_api_client.stack_id)`), but `create` bypasses that scope entirely, letting a stack-A-scoped token create stacks for arbitrary repository B.

### Finding Description
The claimed binding is: `current_api_client.stack_id == the only stack/repository the client may read or mutate`.

This binding holds for `show`/`update`/`destroy`/`refresh` because they all resolve the target record through `stack` → `stacks.from_param!(params[:id])`, and `stacks` is defined as: [1](#0-0) 
`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`. Attempting to touch a stack outside that scope raises `RecordNotFound` via `from_param!`.

`create`, however, never goes through `stacks`: [2](#0-1) 
```ruby
def create
  stack = Stack.new(create_params)
  stack.repository = repository
  stack.save
  render_resource(stack)
end
```
`repository` is `Repository.find_or_create_by(owner: repo_owner, name: repo_name)` taken straight from request params: [3](#0-2) 

The only gate on `create` is the permission check: [4](#0-3) 
`require_permission :write, :stack, only: %i[create update destroy]`, which calls `current_api_client.check_permissions!(:write, :stack)`: [5](#0-4) 
This only checks that `"write:stack"` is in the `permissions` array; it never inspects `stack_id` at all. So an `ApiClient` record whose `stack_id` is set to stack A's id, but which holds `write:stack` permission, can `POST /api/stacks` with `repo_owner`/`repo_name` for a completely unrelated repository B and successfully create (or, if it already exists, attempt to create) a `Stack` for B — the very read/write scoping that protects every other endpoint is absent here.

Confirmed by existing test fixtures/tests: the test `"#create creates a stack and renders it back"` in `test/controllers/api/stacks_controller_test.rb` authenticates with the default `@client` (scoped to the `shipit` stack per `setup`) and successfully creates a stack for `rails/rails`, a repository unrelated to the authenticated client's own stack, with no restriction: [6](#0-5) 
This existing test already demonstrates the exact divergence the question describes — no additional guard (`ExplicitParameters` schema, `Repository` format validators, `Stack` environment validators) checks the created repository/stack against `current_api_client.stack_id`; those only validate format/uniqueness of the new record, not authorization scope.

### Impact Explanation
Any `ApiClient` token holding `write:stack` — regardless of its `stack_id` scoping — can create `Stack` records for arbitrary repositories it was never authorized to touch. This is a cross-tenant authorization break: a client credential intended to be limited to repository/stack A can provision stacks (and, by extension, initiate deploy/CI tracking configuration) for repository B. This matches "a payload for one repository mutating another's stack" (Critical) since the write is not bound to the token's declared scope. The blast radius covers every multi-tenant Shipit deployment that issues stack-scoped API tokens under the assumption that `stack_id` restricts what a token can create, not just what it can read/update by id.

### Likelihood Explanation
Preconditions: the attacker must already possess a valid `ApiClient` credential with `write:stack` permission (even one intentionally scoped to a single stack via `stack_id`). Given that credential, exploitation is a single unauthenticated-repository-choice `POST /api/stacks` request — trivial and fully repeatable against any repository owner/name pair. No GitHub secrets, webhook signatures, or session state are required beyond the token itself. Note that per the audit's threat model ("attacker is unprivileged only ... they hold no ... `ApiClient` token"), an attacker with zero Shipit-issued credentials cannot reach this path at all; the scenario requires possession of *some* legitimate but narrowly-scoped API token, which is a materially different (and lesser) privilege level than the stated "unprivileged internet/GitHub user."

### Recommendation
In `StacksController#create`, when `current_api_client.stack_id` is set, reject (403) creation attempts unless the resolved `repository` matches the repository already bound to that stack. General mitigation: compare `current_api_client.stack_id` against the target repository/stack for every mutating action, not just for id-based lookups.

### Proof of Concept
Minitest plan under `test/controllers/api/stacks_controller_test.rb`:
```ruby
test "#create with a stack-scoped client can create a stack for an unrelated repository" do
  authenticate!(:here_come_the_walrus) # client scoped to stack_id of stack A (e.g. :soc)
  scoped_stack = @client.stack
  unrelated_repo_owner, unrelated_repo_name = 'rails', 'rails' # repository B, unrelated to stack A

  assert_not_equal scoped_stack.repository.owner, unrelated_repo_owner

  assert_difference -> { Stack.count } do
    post :create, params: {
      repo_owner: unrelated_repo_owner,
      repo_name: unrelated_repo_name,
      environment: 'staging',
      branch: 'staging'
    }
  end

  assert_response :ok
  created_stack = Stack.last
  # Binding violated: current_api_client.stack_id (== scoped_stack.id) != created_stack.id / created_stack.repository
  assert_not_equal @client.stack_id, created_stack.id
  assert_not_equal scoped_stack.repository, created_stack.repository
end
```
This asserts both sides of the equality (`current_api_client.stack_id` vs. the repository/stack actually mutated) diverge, proving the scope binding is broken.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L111-121)
```ruby
      def repository
        @repository ||= Repository.find_or_create_by(owner: repo_owner, name: repo_name)
      end

      def repo_owner
        params[:repo_owner]
      end

      def repo_name
        params[:repo_name]
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
