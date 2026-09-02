### Title
API client token scoped to one stack can read CCMenu status of any other stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution helper used by every other API controller, breaking the invariant that an `ApiClient` token is confined to the single `Stack` it was issued for. Any token carrying `read:stack`, even one deliberately scoped to a single stack, can be replayed against `Api::CCMenuController#show` with a different `stack_id` to read another stack's deploy status.

### Finding Description
Every other API controller resolves the target stack through `BaseController#stack`, which is built on `BaseController#stacks`: [1](#0-0) 

`stacks` restricts the visible `Stack` set to `current_api_client.stack_id` when the authenticated `ApiClient` is scoped to one (`ApiClient#stack` is an optional `belongs_to`, e.g. fixture `here_come_the_walrus` is scoped to stack `shipit` with only `read:stack`): [2](#0-1) [3](#0-2) 

`Api::CCMenuController`, however, defines its own private `stack` method that bypasses this scoping entirely and resolves the stack from the raw `params[:stack_id]` against the full `Stack` table: [4](#0-3) 

The controller's only authorization gate is `require_permission :read, :stack`, which just calls `current_api_client.check_permissions!(:read, :stack)` — a permission-name check, not a per-stack ownership check: [5](#0-4) [6](#0-5) 

So the binding that should hold — "stack a token authorizes == stack the request touches" — is enforced everywhere except this controller. `CCMenuController` also supports an alternate, unauthenticated-looking `token` query param path for authentication (`ApiClient.authenticate(params[:token])`), consistent with how CCMenu URLs are meant to be fetched and reused as a bookmarkable/polling URL: [7](#0-6) 

### Impact Explanation
Any holder of a valid `ApiClient` token with `read:stack` permission — including a token that an operator deliberately scoped to a single stack via the `stack_id` column so it could not see other stacks — can substitute an arbitrary `stack_id` in the CCMenu request and read that other stack's latest deploy/rollback state, build id, and status (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.), rendered from `stack.deploys_and_rollbacks.last`. This is an unauthorized cross-stack read of stack/deploy state that the token was never granted access to, matching the "unauthenticated/unauthorized read of stack state or deploy output" class of impact.

### Likelihood Explanation
Exploitation only requires possession of any single valid, non-revoked `ApiClient` token that has the `read:stack` permission (the lowest tier of API permission) — no session, GitHub App credentials, or elevated permissions are needed. The scoped-token bypass is a straightforward parameter substitution (`stack_id`) on an existing, documented endpoint (`api_stack_ccmenu_url`), and CCMenu tokens/URLs are explicitly designed to be shared/embedded in third-party CI dashboard tools, increasing the chance such a token leaks or is deliberately handed to a lower-trust consumer that is expected to be confined to one stack.

### Recommendation
Make `Api::CCMenuController#stack` go through the same scoped lookup as the rest of the API (`stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`), so a stack-scoped `ApiClient` cannot resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to stack A: `ApiClient.create!(creator: user, name: 'x', stack: stack_a, permissions: ['read:stack'])`, and get its `authentication_token`.
2. Send `GET /api/<stack_a_owner>/<stack_a_repo>/<stack_a_env>/ccmenu.xml?token=<token>` — succeeds as expected, per the resolved stack A.
3. Send `GET /api/<stack_b_owner>/<stack_b_repo>/<stack_b_env>/ccmenu.xml?token=<token>` using the same token but a different, unrelated stack B's `stack_id` path.
4. Because `CCMenuController#stack` calls `Stack.from_param!` instead of the scoped `stacks.from_param!`, the request succeeds and returns stack B's deploy status/XML, even though the token is only supposed to authorize reads of stack A.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-22)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/models/shipit/api_client.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
