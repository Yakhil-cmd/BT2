### Title
CCMenu API endpoint bypasses ApiClient stack-scoping, letting a stack-scoped token read status of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces the equality binding: `ApiClient#stack_id` (the stack a token is authorized for) == the stack a request actually touches. This is implemented by scoping stack lookups through `stacks.from_param!` rather than `Stack.from_param!` directly. `Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly, skipping the scoping entirely, so a stack-scoped `ApiClient` can be used to fetch CCMenu status for stacks it was never authorized for.

### Finding Description
`BaseController#stacks` restricts the queryable set of stacks to the one the authenticated `ApiClient` is bound to: [1](#0-0) 

`ApiClient` has an optional `belongs_to :stack`, and `check_permissions!` only validates the coarse `operation:scope` string (e.g. `read:stack`) — it never checks which specific stack is being accessed: [2](#0-1) 

The fixture `here_come_the_walrus` demonstrates that a real, stack-bound `ApiClient` with only `read:stack` permission is a supported configuration: [3](#0-2) 

Every other API controller (`TasksController`, `DeploysController`, `RollbacksController`, `MergeRequestsController`, `LocksController`, `ReleaseStatusesController`, `OutputsController`, `CommitsController`, `StacksController`) resolves the target stack through the inherited, scoped `stack`/`stacks` helper, so the `stack_id` binding on the token is enforced for every one of them: [4](#0-3) [5](#0-4) 

`CCMenuController`, however, redefines `#stack` to resolve against the entire `Stack` relation, bypassing the `current_api_client.stack_id` filter entirely: [6](#0-5) 

The route confirms `stack_id` is attacker-controlled request input, independent of the authenticated client's bound stack: [7](#0-6) 

Before the request: `ApiClient#stack_id == S1` (the only stack the token should ever expose). After the request: an attacker who holds this token can supply `stack_id=S2` (any other stack in the installation) to `GET /api/stacks/:stack_id/ccmenu` and the controller happily resolves and renders `S2`'s CCMenu project (name, `lastBuildStatus`, `lastBuildLabel`, etc.), because `Stack.from_param!` ignores the `stack_id` scope that `stacks.from_param!` would have enforced. This breaks the binding: `stack the token authorizes == stack the endpoint touches`.

### Impact Explanation
This matches the High-impact category "unauthenticated/unauthorized read of stack state" — a token scoped to `read:stack` on one stack can read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, lock state, activity, webUrl) of every other stack in the Shipit installation, including private/internal stacks the token holder has no legitimate authorization for. It is a confidentiality/authorization-boundary violation rather than RCE or credential exfiltration, but it directly crosses the stack-authorization boundary that the rest of the API deliberately enforces.

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` authentication token that is bound to a `stack_id` (a normal, documented configuration, as shown by the `here_come_the_walrus` fixture) and knowledge/guessing of another stack's `owner/name/environment` param (which is often public, e.g. visible in the GitHub org/repo name and typical environment names like `production`/`staging`). No privileged access, GitHub App key, or session is needed beyond the existing scoped API token — this is exploitable by anyone already holding a legitimately-issued, narrowly-scoped read-only token.

### Recommendation
Remove the private `stack` override in `Shipit::Api::CCMenuController` (and its `authenticate_api_client` override, if query-string tokens are still desired) so that it relies on `BaseController#stack`/`#stacks`, ensuring the `current_api_client.stack_id` scope is enforced identically to every other API controller. If query-string token auth must be preserved for CCMenu clients, still resolve the stack through `stacks.from_param!` after authentication.

### Proof of Concept
1. Create (or use an existing) stack-scoped `ApiClient` bound to `stack_id = S1` with only `read:stack` permission — e.g., fixture `here_come_the_walrus` (`test/fixtures/shipit/api_clients.yml`, lines 12-17).
2. Using this client's `authentication_token`, issue `GET /api/stacks/*other_owner/other_repo/other_env/ccmenu?token=<token>` where the path refers to stack `S2`, a stack the client is not scoped to.
3. Observe that `Shipit::Api::CCMenuController#stack` resolves via `Stack.from_param!(params[:stack_id])` (app/controllers/shipit/api/ccmenu_controller.rb, lines 29-31), bypassing `stacks.from_param!`'s `current_api_client.stack_id` filter, and the controller renders `S2`'s CCMenu XML (name, lastBuildStatus, etc.) even though `check_permissions!` never verified the token is authorized for `S2` specifically.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L39-43)
```ruby
      private

      def task
        stack.tasks.find(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```
