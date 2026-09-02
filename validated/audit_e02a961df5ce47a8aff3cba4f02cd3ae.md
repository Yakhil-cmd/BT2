### Title
CCMenu API token can be used to read the CI status of any stack, not just the stack it was scoped to - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` authenticates the request by resolving an `ApiClient` from a `token` query-string parameter, but it never checks that the resolved `ApiClient`'s `stack_id` matches the `stack_id` in the URL. It resolves the target `Stack` directly from `params[:stack_id]` instead of scoping through `current_api_client`. This breaks the binding "the stack a token authorises" vs. "the stack it touches."

### Finding Description
`Api::BaseController` establishes the correct binding for every other API controller: a request is scoped to `current_api_client.stack_id` when the client has one, and only unscoped clients see `Stack.all`: [1](#0-0) 

`Api::CCMenuController`, however, overrides both the authentication and the stack-resolution logic: [2](#0-1) 

`authenticate_api_client` only verifies that `params[:token]` maps to *some* valid `ApiClient` via `ApiClient.authenticate`, which merely checks the HMAC-signed id and returns the record: [3](#0-2) 

`show` then calls `stack`, which is redefined in `CCMenuController` to build the `Stack` straight from `params[:stack_id]` — completely bypassing the `current_api_client.stack_id` check that `BaseController#stack` performs for every other endpoint: [4](#0-3) 

Because `ApiClient` supports an optional per-stack scope (`belongs_to :stack, optional: true`) precisely so a token can be restricted to one stack: [5](#0-4) 

any holder of a valid, `read:stack`-permitted token — even one legitimately scoped to Stack A — can request `/api/stacks/:stack_id/ccmenu.xml?token=...` for Stack B and receive Stack B's deploy/rollback status, because `CCMenuController#stack` never consults `current_api_client.stack_id`.

### Impact Explanation
This is an authorization-scope escalation: a credential that is supposed to authorize read access to one stack's CI/deploy status can be used to read the state of every stack in the installation. This matches the in-scope "High" impact category of escalation into unauthenticated/unauthorized read of stack state via a token that should not have that scope.

### Likelihood Explanation
Any party who legitimately obtains one scoped `read:stack` CCMenu token (e.g. a CI/CCMenu integration configured for a single stack) can trivially exploit this by changing the `stack_id` route parameter — no additional privilege or session is required, only the token they already legitimately hold.

### Recommendation
`Api::CCMenuController#stack` should resolve the stack the same way `Api::BaseController#stack` does, i.e. through `stacks.from_param!(params[:stack_id])` where `stacks` is restricted to `current_api_client.stack_id` when present, instead of calling `Stack.from_param!` directly on the raw parameter.

### Proof of Concept
1. An administrator creates (or the app auto-creates via `CCMenuUrlController#client`) an `ApiClient` intended to be scoped to Stack A (`stack_id: A.id`, `permissions: ['read:stack']`) and obtains its `authentication_token`.
2. The attacker (holder of that token) issues:
   `GET /api/stacks/B/ccmenu.xml?token=<Stack-A-scoped-token>`
3. `authenticate_api_client` in `Api::CCMenuController` successfully authenticates the token (it only validates the signature, not the stack scope).
4. `show` calls `stack`, which is `Stack.from_param!(params[:stack_id])` = Stack B, bypassing the `current_api_client.stack_id` check present in `Api::BaseController#stack`.
5. The response renders Stack B's latest deploy/rollback CI status even though the token was only meant to authorize Stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-25)
```ruby
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
```

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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
```

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end
```
