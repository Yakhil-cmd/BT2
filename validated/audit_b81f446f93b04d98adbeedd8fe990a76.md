### Title
`StacksController#create` ignores `current_api_client.stack_id` scope, letting a stack-scoped `write:stack` token create stacks for arbitrary repositories - ([File: app/controllers/shipit/api/stacks_controller.rb])

### Summary
Every other action in `Shipit::Api::StacksController` (and `BaseController`) resolves the target stack through the `stacks` scope, which restricts a scoped `ApiClient` to `Stack.where(id: current_api_client.stack_id)`. `#create` never goes through that scope: it builds a brand-new `Stack.new(create_params)` and assigns `stack.repository = repository` from attacker-supplied `repo_owner`/`repo_name`, with no check that the client's `stack_id` corresponds to that repository.

### Finding Description
The intended binding is: `current_api_client.stack_id == target_stack.id` (or equivalently `current_api_client.stack.repository == repository`) for any mutation performed by a stack-scoped token. This is enforced in `BaseController#stacks`: [1](#0-0) 

and used by `#update`, `#destroy`, `#show`, `#refresh` via `stack` (`stacks.from_param!(params[:id])`): [2](#0-1) 

`#create`, however, bypasses `stacks`/`stack` entirely: [3](#0-2) 

The only guard on `create` is `require_permission :write, :stack`, which calls `ApiClient#check_permissions!` — a pure permission-string check that has no knowledge of `stack_id`: [4](#0-3) 

So an `ApiClient` created with `stack_id` set to stack A (e.g. via the admin UI/`ApiClientsController`) and permission `write:stack` — intended to be limited to acting on stack A — can `POST /api/stacks` with `repo_owner`/`repo_name` for an unrelated repository B. `repository` is resolved via `Repository.find_or_create_by(owner: repo_owner, name: repo_name)`: [5](#0-4) 

and a fresh `Stack` for repository B is persisted, completely outside the token's intended scope. No repository-format validator or `ExplicitParameters` schema check ties `repo_owner`/`repo_name` back to `current_api_client.stack_id`.

The existing fixture `here_come_the_walrus` (stack-scoped, `read:stack` only) demonstrates that stack-scoped clients are a supported configuration: [6](#0-5) 

An operator granting such a client `write:stack` (a plausible configuration, since `write:stack` is a normal permission an admin can assign alongside `stack_id`) unintentionally grants it the ability to create stacks for any repository on the Shipit instance, not just the one named by `stack_id`.

### Impact Explanation
A holder of a stack-A-scoped `write:stack` token can create new `Stack` records for arbitrary repositories/environments/branches, effectively acting as an unscoped stack-creation client. Since new stacks can be configured with `deploy_url`, `continuous_deployment`, `merge_queue_enabled`, etc., and stack creation is a prerequisite step toward deploy/merge/webhook processing for that repository, this breaks the tenant isolation the `stack_id` scoping is designed to provide. This is repeatable for any number of repositories with a single credential, matching the "payload for one repository mutating another's stack" class of impact (Critical), though note this creates a new stack for B rather than mutating an existing one — the exploit requires that no stack for B/environment/branch already exists (otherwise a uniqueness validation error occurs, as shown in the existing test `"#create fails to create stack if it already exists"`).

### Likelihood Explanation
Requires possession of a valid `ApiClient` token that (a) has `write:stack` permission and (b) is scoped via `stack_id` to a specific stack. Such tokens can be issued for third-party integrations expected to be limited to one repository/stack. Given such a token, the attack is a single unauthenticated-repository `POST /api/stacks` request with attacker-chosen `repo_owner`/`repo_name` — no other secrets or privileges are needed beyond the token itself.

### Recommendation
In `StacksController#create`, validate that when `current_api_client.stack_id?` is true, the resolved `repository` matches `current_api_client.stack.repository` (or reject the request with `403`/`422` otherwise), mirroring the scoping already applied by `BaseController#stacks`.

### Proof of Concept
```ruby
test "#create is rejected for a stack-scoped client targeting a different repository" do
  scoped_client = ApiClient.create!(
    name: 'Scoped', creator: shipit_users(:walrus),
    stack: shipit_stacks(:shipit), permissions: ['write:stack']
  )
  authenticate_with(scoped_client) # helper to set Authorization header to scoped_client.authentication_token

  assert_no_difference -> { Stack.count } do
    post :create, params: { repo_owner: 'unrelated-org', repo_name: 'unrelated-repo', branch: 'main' }
  end
  assert_response :forbidden
end
```
Currently this test fails: `Stack.count` increases by 1 and the response is `200 OK`, because `create` never compares `current_api_client.stack_id`/`current_api_client.stack.repository` against the requested `repo_owner`/`repo_name`.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L36-41)
```ruby
      def create
        stack = Stack.new(create_params)
        stack.repository = repository
        stack.save
        render_resource(stack)
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
