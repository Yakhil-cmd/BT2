### Title
Stack-scoped API token can create unrelated stacks via `Api::StacksController#create` - (File: app/controllers/shipit/api/stacks_controller.rb)

### Summary
An `ApiClient` can be scoped to a single `Stack` via its `stack_id` association, and the API's `stacks` helper enforces that scoping for read/update/destroy/show. However, the `create` action bypasses that scoping entirely: it authorizes solely on the `write:stack` permission and never checks `current_api_client.stack_id`, allowing a token that is supposed to be restricted to one stack to create brand-new stacks for arbitrary repositories.

### Finding Description
`Api::BaseController#stacks` is the trust boundary that is supposed to bind an `ApiClient`'s scope to a specific `Stack`: [1](#0-0) 
This binding equality should be: `stack a token is authorized to touch == current_api_client.stack_id (if set)`.

`StacksController` enforces permissions declaratively: [2](#0-1) 
`require_permission :write, :stack` only checks `ApiClient#check_permissions!`, i.e., whether `"write:stack"` is in the client's `permissions` array: [3](#0-2) 
It performs no comparison against `stack_id` at all — `ApiClient` has no concept of "permitted stack" enforcement beyond the `stacks` scoping helper.

Crucially, `#create` never calls the scoped `stack`/`stacks` helper (which is what applies the `where(id: current_api_client.stack_id)` restriction). Instead it builds a brand new `Stack` directly from `create_params` and an arbitrary attacker-supplied `repo_owner`/`repo_name`: [4](#0-3) [5](#0-4) 

Contrast this with `#update`/`#destroy`/`#show`, which do go through `stack` → `stacks.from_param!`: [6](#0-5) [7](#0-6) 

So the equality that holds for every other write action — `stack the token is bound to == stack the action operates on` — is silently dropped for `create`, because `create` operates on a stack that doesn't exist yet and is therefore never filtered by `stacks`. The scoping mechanism (`stack: shipit_users(:walrus)`-bound clients, e.g. `here_come_the_walrus` fixture) is documented/tested to restrict clients to a single stack for read (`test/controllers/api/stacks_controller_test.rb:217-223`), but no equivalent restriction exists for stack creation.

### Impact Explanation
Any holder of a Shipit API token that was deliberately scoped to a single stack (a common integration pattern — e.g., a CCMenu client created for one stack, or any third-party integration issued a narrowly-scoped, `stack`-bound token with `write:stack`) can use that token to create arbitrary new `Stack` records for any GitHub repository/owner known to Shipit, including repositories the token holder was never meant to have access to. Because stack creation also triggers `sync_github` and eventually `CacheDeploySpecJob`/`GithubSyncJob` against the newly created stack's repository using Shipit's own GitHub App credentials, this lets a narrowly-scoped credential pivot into managing deployment configuration for an unrelated repository — effectively a cross-repository authorization bypass performed with the app's own GitHub credentials once the new stack begins driving webhooks, deploys, and merges for that repo. This matches the "cross-repository writes" / unauthorized-deploy class of impact.

### Likelihood Explanation
Low-to-medium. It requires possession of a valid, stack-scoped `ApiClient` token that happens to carry the `write:stack` permission. Since scoped tokens are intended (by the `stacks` helper's existence) to be constrained to one stack, an operator relying on that scoping as the security boundary — without realizing `create` ignores it — would unintentionally grant a broader-than-expected capability. No additional privilege beyond having such a token is needed; there's no rate limiting or approval step for `create`.

### Recommendation
In `Api::StacksController#create` (and anywhere else `write:stack` is checked without a bound stack), explicitly reject the request if `current_api_client.stack_id` is present, since a stack-scoped client should never be able to create a *new*, different stack. Alternatively, restrict `create` to only "global" (non-stack-scoped) API clients, mirroring the intent already expressed by the `stacks` helper used by every other action in this controller.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to `Stack A` (`stack: stack_a`) with permission `write:stack` (matching the `here_come_the_walrus` fixture pattern in `test/fixtures/shipit/api_clients.yml:12-17`, but with `write:stack` added).
2. Using that client's `authentication_token`, call:
   ```
   POST /api/stacks
     repo_owner=some-other-org
     repo_name=some-other-repo
     environment=production
     branch=main
   ```
3. `require_permission :write, :stack` passes because `"write:stack"` is in the client's permissions — no check is made that the target repo belongs to `stack_a`.
4. `create` builds and saves a new `Stack` for `some-other-org/some-other-repo`, entirely unrelated to `stack_a`, using the app's GitHub credentials to sync it going forward. [4](#0-3)

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L52-67)
```ruby
      def update
        stack.update(update_params)

        update_archived

        render_resource(stack)
      end

      def show
        render_resource(stack)
      end

      def destroy
        stack.schedule_for_destroy!
        head(:accepted)
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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
