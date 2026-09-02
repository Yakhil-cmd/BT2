### Title
Stack-scoped API tokens can create Stacks for arbitrary repositories, bypassing their `stack_id` scope - (File: `app/controllers/shipit/api/stacks_controller.rb`)

### Summary
An `ApiClient` can be scoped to a single stack via its `stack_id` column, which is meant to confine every operation that token performs to that one `Stack`. The `#create` action of `Shipit::Api::StacksController` never applies this scope: it builds a brand-new `Stack` record directly from client-supplied `repo_owner`/`repo_name` params instead of going through the scoped `stacks` relation used by every other action in the controller. A caller holding a token scoped to one stack (with `write:stack` permission) can therefore register new stacks — including with `continuous_deployment: true` — for any GitHub repository, something its token was never authorized to touch.

### Finding Description
`ApiClient#check_permissions!` only validates the operation/scope name (e.g. `write:stack`); it never checks whether the target `Stack` matches `stack_id`: [1](#0-0) 

The scoping is instead enforced ad hoc in `Api::BaseController#stacks`, which restricts the queryable set of stacks to the client's own `stack_id` when one is set: [2](#0-1) 

`Api::StacksController#index`, `#show`, `#update`, `#destroy`, and `#refresh` all route through this scoped `stacks`/`stack` helper: [3](#0-2) 

But `#create` bypasses it entirely — it instantiates a brand-new `Stack` from attacker-supplied params without ever consulting `current_api_client.stack_id`: [4](#0-3) 

The only gate on `#create` is the generic `require_permission :write, :stack` declaration, which — as shown above — checks permission names only, not the stack the token is bound to: [5](#0-4) 

This breaks the intended binding: `stack a token authorizes == stack it touches`. A token minted for stack A (e.g. via the CCMenu flow which creates a `stack`-scoped client, or any admin-issued single-stack token) is supposed to only ever read/write stack A, yet it can call `POST /stacks` to provision entirely new stacks for arbitrary `repo_owner`/`repo_name` values, with attacker-chosen `continuous_deployment`, `merge_queue_enabled`, `branch`, and `deploy_url` attributes.

### Impact Explanation
This is a cross-repository write: a token whose authorization was supposed to be confined to a single stack/repository can instead cause Shipit to begin tracking and managing an arbitrary GitHub repository chosen by the attacker, with `continuous_deployment` optionally enabled. Because Shipit periodically schedules deploys for stacks flagged `continuous_deployment: true` (`Stack.schedule_continuous_delivery`), an attacker-created stack pointed at a repository the attacker controls could later cause Shipit's own GitHub App credentials to be used against that repository outside the boundary the original token was meant to respect.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `write:stack` API token (e.g. a CCMenu token, or any token an administrator intentionally restricted to one stack) can exploit this with a single authenticated API call — no additional privilege escalation is required, only the routine `write:stack` permission that scoped tokens are expected to carry for managing their own stack.

### Recommendation
In `Api::StacksController#create`, reject the request (or ignore `repo_owner`/`repo_name` overrides) whenever `current_api_client.stack_id?` is true and the resulting repository/stack would not match the client's bound `stack_id`. More generally, `ApiClient#check_permissions!` should be extended to also validate that the target resource belongs to `stack_id` whenever the client is stack-scoped, rather than relying on each controller action to remember to filter through `stacks`.

### Proof of Concept
1. Issue (or obtain) an `ApiClient` scoped to stack A: `ApiClient.create!(creator: user, name: 'x', stack_id: stack_a.id, permissions: %w[write:stack])`.
2. Using that token's Basic-Auth credentials, call:
   ```
   POST /stacks
   repo_owner=some-other-org
   repo_name=some-other-repo
   environment=production
   continuous_deployment=true
   ```
3. Observe the request succeeds (`render_resource(stack)` returns `200`) and a new `Stack` for `some-other-org/some-other-repo` is created, even though the token is bound to `stack_a.id` and was never granted permission over `some-other-org/some-other-repo`. [6](#0-5)

### Citations

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L26-41)
```ruby
      params do
        requires :repo_owner, String
        requires :repo_name, String
        accepts :environment, String
        accepts :branch, String
        accepts :deploy_url, String, allow_nil: true
        accepts :ignore_ci, Boolean
        accepts :merge_queue_enabled, Boolean
        accepts :continuous_deployment, Boolean
      end
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
