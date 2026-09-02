### Title
Stack-scoped API tokens can create unrelated stacks, escaping the `ApiClient#stack_id` binding - (File: app/controllers/shipit/api/stacks_controller.rb)

### Summary
Analogous to the `init_if_needed` issue (a caller can mutate protected state outside the boundary the design intends), a Shipit `ApiClient` token that is scoped to a single stack via `stack_id` can call `Api::StacksController#create` to create brand-new `Stack` records for arbitrary repositories, because `create` never routes through the `stacks` scoping helper that every other action in the controller relies on.

### Finding Description
`Api::BaseController` defines the authorization boundary for scoped tokens: [1](#0-0)  — if `current_api_client.stack_id?` is set, the client is meant to only see/touch that one `Stack`. `show`, `update`, `destroy`, and `refresh` in `Api::StacksController` all resolve their target through `stacks.from_param!(params[:id])`, which correctly enforces this scoping: [2](#0-1) .

However, `create` bypasses this binding entirely and instantiates a new record directly: [3](#0-2) . It only checks the coarse-grained `write:stack` permission (`require_permission :write, :stack, only: %i[create update destroy]`, [4](#0-3) ) via `ApiClient#check_permissions!`, which has no notion of `stack_id` at all: [5](#0-4) .

The binding that should hold is: *the stack(s) a token authorizes == the stack(s) the token can touch*. For `create`, before the request: token is bound to `stack_id = X` and holds `write:stack`. After the request: the same token has caused a brand-new `Stack` (for any `repo_owner`/`repo_name` the requester supplies) to be persisted, with `repository = Repository.find_or_create_by(owner: repo_owner, name: repo_name)` [6](#0-5)  — a repository completely unrelated to `X`. The equality is broken: the token's authorized scope (`stack_id = X`) no longer matches the set of stacks it can affect (`X` plus any newly created stack for any repo).

### Impact Explanation
This lets a possessor of a narrowly-scoped API token (issued, per the app's own design, to only manage one stack/repository) provision new deployable stacks tied to arbitrary GitHub repositories, including a `Repository.find_or_create_by` side effect that adds tracking for repos the token was never meant to interact with. Once created, that stack can be targeted for deploys/tasks by anyone else who can also reach the API (or by the same token, since it's the creator's action), effectively expanding write access beyond the intended per-stack authorization boundary. This matches the "escalation into authorization scope" pattern the rules call out (a stack a token authorizes vs. a stack it touches).

### Likelihood Explanation
Any caller in possession of a scoped `ApiClient` token that has `write:stack` in its `permissions` (a normal, documented permission for automation tokens, independent of whether `stack_id` is set) can exploit this with a single unauthenticated-w.r.t.-scope API call — no additional privilege beyond having such a token is required, and the token is explicitly supposed to be confined to one stack.

### Recommendation
In `Api::StacksController#create`, reject the request (or ignore `repo_owner`/`repo_name` and force association to `current_api_client.stack`) when `current_api_client.stack_id?` is present, so a stack-scoped token can never bring a different stack into existence. Alternatively, have `ApiClient#check_permissions!` take the target repository/stack into account for `write:stack` on `create`, consistent with how `stacks` scopes read/update/destroy.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <shipit-stack-id>` with `permissions: ['write:stack']` (a legitimate, narrowly-scoped automation token per `test/fixtures/shipit/api_clients.yml`, e.g. modeled on `here_come_the_walrus`).
2. Authenticate with that token's `authentication_token` against `POST /api/stacks` (per `test/controllers/api/stacks_controller_test.rb`'s `post :create` pattern) with `repo_owner`/`repo_name` for a repository the token was never scoped to, e.g.:
   ```
   POST /api/stacks
   Authorization: Basic <client_id>--<token>
   repo_name=rails&repo_owner=rails&environment=staging&branch=staging
   ```
3. Observe `Stack.count` increments and a new `Stack`/`Repository` row exists for `rails/rails`, even though `current_api_client.stack_id` still points only at the original stack — demonstrating the scoped token touched a stack outside its authorized set.

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
