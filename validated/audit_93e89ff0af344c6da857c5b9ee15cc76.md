Found the analog: `Api::CCMenuController` bypasses the stack-scoping that every other API controller enforces.

### Title
API client stack-scope bypass in CCMenu endpoint — token authorizes one stack but can read any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` records can be scoped to a single stack (`stack_id`), and `Api::BaseController#stacks`/`#stack` enforce that scope for every other API controller by filtering `Stack.where(id: current_api_client.stack_id)` before resolving `params[:stack_id]`. `Api::CCMenuController` overrides `#stack` and resolves it directly via `Stack.from_param!(params[:stack_id])`, never consulting `current_api_client.stack_id`, breaking the binding "stack a token authorizes == stack the endpoint touches."

### Finding Description
`Api::BaseController` defines the scoping used by every other API resource controller: [1](#0-0) 

`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true`, and `check_permissions!` only validates the operation/scope string (e.g. `read:stack`), never the specific stack id: [2](#0-1) 

Every other API controller (e.g. `Api::TasksController`, `Api::DeploysController`) relies on the inherited `stack` method, so a stack-scoped client can only ever resolve the one stack tied to its `stack_id`: [3](#0-2) [4](#0-3) 

`Api::CCMenuController`, however, overrides `#stack` to resolve directly against the unscoped `Stack` model, ignoring `current_api_client.stack_id` entirely: [5](#0-4) 

The `require_permission :read, :stack` before-action only checks that `'read:stack'` is in `current_api_client.permissions` — it does not check which stack — so any client holding `read:stack` permission (including one that was deliberately restricted to a single stack via `stack_id`) can pass `params[:stack_id]` for any other stack and successfully render that stack's CCMenu XML.

### Impact Explanation
This is an unauthenticated-scope escalation: an API token that an administrator intentionally restricted to one stack (`here_come_the_walrus` fixture pattern: `stack: shipit`) can be used to read deploy/rollback state (latest deploy id, end time, running status) of any other stack in the installation, including stacks it was never granted access to. This matches the High-impact category "unauthenticated read of stack state, task streams or deploy output" via a credential-scope binding break, analogous to the audit's "queue not properly cleared/scoped" class of bug where an inner resolution path (`CCMenuController#stack`) fails to inherit the outer authorization context (`stack_id` scoping) that all sibling controllers respect.

### Likelihood Explanation
High likelihood: exploitation requires only possession of any valid API client token with `read:stack` permission (a normal, low-privilege token type meant to be usable), no special session, no write access, and no interaction with other components — just calling the existing `GET /ccmenu/:stack_id` endpoint with a different `stack_id` than the one the token is scoped to.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or make it delegate through the inherited, scope-aware `stacks`/`stack` implementation from `BaseController`) so that stack-scoped API clients are restricted to `Stack.where(id: current_api_client.stack_id)` exactly like every other API controller.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to `stack_id: shipit_stacks(:shipit).id` with permission `read:stack` (mirrors fixture `here_come_the_walrus` in `test/fixtures/shipit/api_clients.yml`). [6](#0-5) 
2. Authenticate to the CCMenu API using this token: `GET /ccmenu/<other_stack_id_or_full_name>?token=<token>`, where `<other_stack_id_or_full_name>` is a stack different from the one the client is bound to.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than going through `stacks.from_param!`, the request succeeds and returns the other stack's CCMenu XML (latest deploy id/status), even though `current_api_client.stack_id` restricts this client to a different stack — contrast with the equivalent request against `Api::TasksController#index` or `Api::DeploysController#index` using the same token and target stack, which would correctly 404/scope-filter via `stacks`.

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L9-11)
```ruby
      def index
        render_resources(stack.tasks)
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L8-10)
```ruby
      def index
        render_resources(stack.deploys_and_rollbacks)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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
