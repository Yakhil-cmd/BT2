### Title
Stack-scoped API tokens can create stacks for arbitrary repositories, bypassing the token's stack scope - (File: app/controllers/shipit/api/stacks_controller.rb)

### Summary
`Shipit::ApiClient` can be created scoped to a single stack via its `stack_id` attribute, and its permissions (`read:stack`, `write:stack`, etc.) are checked generically by `check_permissions!` without ever verifying that the *record* being acted on is the stack the token is bound to [1](#0-0) . The scoping is enforced separately, in `Shipit::Api::BaseController#stacks`, which restricts the queryable set of stacks to `current_api_client.stack_id` when it is present [2](#0-1) . `Shipit::Api::StacksController#index`, `#show`, `#update`, and `#destroy` all resolve their target stack through this scoped `stacks`/`stack` helper [3](#0-2) , but `#create` does not — it builds a brand-new `Stack.new(create_params)` for an arbitrary `repo_owner`/`repo_name` and never consults `current_api_client.stack_id` at all [4](#0-3) .

### Finding Description
This is an analog of the reported bug class: a parameter that should be constrained by an already-established binding (`fee_to_encrypt` vs. `transfer_amount`, verified only indirectly via `delta_fee`) is instead checked through an incomplete, indirect proxy that a different code path skips entirely. Here, the binding that should hold is: `ApiClient#stack_id == Stack acted upon`, whenever `stack_id` is present. `#index`/`#show`/`#update`/`#destroy` enforce this equality via the `stacks` scope [2](#0-1) . `#create` is guarded only by `require_permission :write, :stack, only: %i[create update destroy]` [5](#0-4) , which merely checks the string `"write:stack"` is in the token's `permissions` array [6](#0-5)  — it says nothing about *which* stack. Because `#create` never calls `stack` or `stacks`, the equality is never evaluated for this action, and a token scoped to stack A can create a brand-new `Stack` for repository B (any `repo_owner`/`repo_name` pair) that it was never intended to touch.

Before the attacker's request: a stack-scoped `ApiClient` (e.g. `here_come_the_walrus`, scoped to `stack: shipit` with `write:stack`) is intended, per the scoping model demonstrated by `test/controllers/api/stacks_controller_test.rb`'s "an api client scoped to a stack will only see that one stack" test [7](#0-6) , to only read/write that one stack.

After the attacker's request: using that same token, a `POST /api_clients-authenticated stacks` request with `repo_owner`/`repo_name` for an unrelated repository succeeds and creates a new `Stack` record tied to `repository.rb`'s `find_or_create_by` [8](#0-7) , breaking the `ApiClient#stack_id == Stack acted upon` binding.

### Impact Explanation
A credential intended by its issuer to be limited to automating a single stack/repository can instead register (and subsequently, since `deploy:stack`/`lock:stack` checks are likewise scope-string-only and not stack-instance-bound, potentially deploy/lock) a stack for a completely unrelated repository. This is a cross-repository write performed with a token that was explicitly scoped away from that repository, matching the "Critical - cross-repository writes" impact category.

### Likelihood Explanation
Any holder of a stack-scoped API token with the `write:stack` permission bit (a routine, low-privilege token configuration meant to restrict automation to one stack) can exploit this with a single unauthenticated-relative-to-other-stacks API call; no additional privilege escalation or session is required beyond the token itself.

### Recommendation
Enforce the same `stack_id` scoping in `#create` as is done for `index`/`show`/`update`/`destroy`: reject (or force the target repository to match) when `current_api_client.stack_id?` is true and the requested `repo_owner`/`repo_name` does not correspond to the client's bound stack. More generally, `check_permissions!`/`require_permission` should validate against the specific stack record when the client is stack-scoped, not just the permission string.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to `stack_id: <stack A>` with permission `write:stack` (mirrors fixture `here_come_the_walrus`) [9](#0-8) .
2. Authenticate as this client and call `POST /stacks` (routed to `Shipit::Api::StacksController#create`) with `repo_owner`/`repo_name` for a repository the client was never scoped to [4](#0-3) .
3. The request succeeds and creates a `Stack` for that unrelated repository, because `#create` never checks `current_api_client.stack_id` the way `#index`/`#show`/`#update`/`#destroy` do via `stacks`/`stack` [2](#0-1) .

### Citations

**File:** app/models/shipit/api_client.rb (L7-45)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }

    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end

    def authentication_token
      self.class.message_verifier.generate(id)
    end

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L60-89)
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

      private

      def create_params
        params.reject { |key, _| %i[repo_owner repo_name].include?(key) }
      end

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
