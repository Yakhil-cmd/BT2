### Title
Stack-scoped API token can read the CCMenu deploy status of any stack — ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution helper inherited from `Shipit::Api::BaseController` in a way that no longer honors the stack scope bound to the authenticating `ApiClient`. The token authorizes read access to a single stack (`ApiClient#stack_id`), but the code acts on whatever `stack_id` is supplied in the request path, breaking the binding `stack authorized by token == stack acted upon`.

### Finding Description
`Shipit::Api::BaseController` establishes the security invariant that a request's target stack must be drawn from the set of stacks the authenticated `ApiClient` is scoped to: [1](#0-0) 

`stacks` filters to `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?`), otherwise `Stack.all`. Permission checking via `require_permission` only checks that the client holds the `read:stack` permission string; it performs no per-object scoping — scoping is enforced exclusively by the `stack`/`stacks` helper. [2](#0-1) 

`CCMenuController` inherits from `BaseController` and requires `read:stack`, but it defines its own private `stack` method that bypasses the scoped `stacks` relation entirely, resolving directly against the full `Stack` table using only the URL parameter: [3](#0-2) 

Specifically:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
instead of the inherited, scope-enforcing:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
`ApiClient` explicitly supports being scoped to a single stack via `belongs_to :stack, optional: true`, and `authenticate_api_client` in `CCMenuController` allows authentication purely via a `?token=` query parameter: [4](#0-3) [5](#0-4) 

The equality that should hold — `current_api_client.stack_id == resolved stack.id` (when scoped) — is broken: `CCMenuController#show` acts on any `stack_id` present in the request, regardless of what stack the token was scoped/authorized for.

### Impact Explanation
This is an authorization boundary break matching "unauthenticated/unauthorized read of stack state, task streams or deploy output" — a stack-scoped, low-privilege (`read:stack`-only) token can be replayed against every other stack in the Shipit instance to read that stack's deploy status, last build label, activity, and web URL (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc., rendered by the `ccmenu/project` view), none of which the token was ever authorized to see. Any leaked or shared CCMenu token (these are embedded in plaintext URLs used by CI dashboard tools such as CCMenu clients) grants read access to the deploy status of the entire Shipit installation, not just the one stack it was minted for.

### Likelihood Explanation
The vulnerable code path requires only knowledge of a valid `read:stack`-scoped token (which is by design embedded in a plain-text URL meant for third-party CI dashboard tools) and the ability to change one path parameter (`stack_id`) in the request. No additional privilege, session, or GitHub credential is required beyond possessing that single token — the exact class of "authorized scope vs. acted-upon scope" mismatch described in the analog rules.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation inherited from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the stack acted upon is always constrained to the stack(s) the authenticated `ApiClient` is authorized for.

### Proof of Concept
1. Obtain (or receive, e.g. via a shared CCMenu dashboard URL) a `read:stack`-only `ApiClient` token whose `stack_id` is bound to Stack A.
2. Send `GET /api/stacks/<STACK_B_ID_OR_PARAM>/ccmenu.xml?token=<token_scoped_to_A>`.
3. `authenticate_api_client` succeeds because `ApiClient.authenticate(params[:token])` only validates the signature, not the scope; `require_permission :read, :stack` succeeds because the client holds `read:stack`; `stack` resolves Stack B directly via `Stack.from_param!`, bypassing the `stacks` scoping filter.
4. The response contains Stack B's CCMenu project XML (build status, last build label, etc.) even though the token was never authorized for Stack B — demonstrating the `token-authorized-stack != stack-acted-upon` bypass.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
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

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
  end
end
```

**File:** app/models/shipit/api_client.rb (L1-20)
```ruby
# frozen_string_literal: true

module Shipit
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
```
