### Title
Stack-scoped ApiClient token can create and control stacks outside its authorized `stack_id` - (File: app/controllers/shipit/api/stacks_controller.rb)

### Summary
The Sherlock report's root cause is a binding that is supposed to hold ("a validator's identity == the array/state actually being mutated") but is not enforced on a specific operation (`setValidatorAddress`), letting an actor operate outside the scope it should be limited to. The equivalent binding in shipit-engine is "a stack an `ApiClient` token is authorized for == the stack the API action actually touches." That binding holds for `stack`-scoped read/write endpoints via the `stacks` helper, but is broken for `Api::StacksController#create`.

### Finding Description
`ApiClient` records can be scoped to a single stack via `stack_id` [1](#0-0) . `Api::BaseController#stacks` and `#stack` enforce that scoping for every action that resolves a stack through `stacks.from_param!` [2](#0-1) .

`Api::StacksController#create`, however, never calls `stacks` or `stack`. It builds a brand-new `Stack` directly from client-supplied `repo_owner`/`repo_name`/`branch`/`environment` params and a `Repository` that is found-or-created ad hoc [3](#0-2) [4](#0-3) . The only gate is `require_permission :write, :stack`, which is enforced by `ApiClient#check_permissions!`, a pure string-membership check against the `permissions` array that has no knowledge of `stack_id` at all [5](#0-4) .

This breaks the equality `token.stack_id == stack.id` that every other stack-scoped endpoint (`show`, `update`, `destroy`, `refresh`, deploys, tasks, etc.) relies on for authorization: an `ApiClient` deliberately narrowed to one stack (e.g. `here_come_the_walrus` fixture, `stack: shipit`, holding `write:stack`) [6](#0-5)  can still call `create` to spin up an entirely new `Stack` for any `repo_owner`/`repo_name` it chooses, becoming that new stack's creator and thereby the entity in control of subsequent deploys/rollbacks on it.

### Impact Explanation
An attacker holding a deliberately scope-limited API token (e.g. leaked/handed out for CI use on one project, intended to only touch that one stack) can use it to create new `Stack` records against arbitrary GitHub repositories — including ones the token issuer never intended the holder to interact with — and then drive deploy/rollback/task-trigger operations for those new stacks (all of which are correctly `stack_id`-scoped once the stack exists, but the scoping is meaningless because the attacker created the stack itself). This is a cross-repository write / unauthorized-deploy-adjacent escalation caused entirely by `create` bypassing the `stack_id` scoping binding that the rest of the API enforces.

### Likelihood Explanation
Any caller holding valid Basic-Auth credentials for an `ApiClient` with `write:stack` permission can trigger this with a single unauthenticated-of-scope POST; no GitHub state, admin console access, or additional secrets are required beyond the token itself (which is the expected credential for using the API at all). The `write:stack` permission is commonly granted for legitimate stack-scoped automation, making this reachable in normal deployments.

### Recommendation
In `Api::StacksController#create`, reject the request (403) if `current_api_client.stack_id?` is true, or otherwise restrict stack creation to unscoped ("global") `ApiClient`s only, mirroring the scoping already enforced by `Api::BaseController#stacks`/`#stack`.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A>` with `permissions: ['write:stack']` (mirrors fixture `here_come_the_walrus`) [6](#0-5) .
2. Authenticate with that token and call:
   `POST /api/stacks` with `repo_owner: 'victim-org'`, `repo_name: 'victim-repo'`, `branch: 'main'`, `environment: 'production'`.
3. `require_permission :write, :stack` passes (permission string matches) [7](#0-6) .
4. `create` builds and saves a new `Stack` tied to `Repository.find_or_create_by(owner: 'victim-org', name: 'victim-repo')`, entirely outside the token's authorized `stack_id` [3](#0-2) , confirming the `stack_id` binding is not enforced on this action (contrast with the existing test `"#create creates a stack and renders it back"` which shows creation succeeds purely on permission string, independent of any stack scope) [8](#0-7) .

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
