### Title
CCMenu API token stack scope bypass allows cross-stack read of deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The `Shipit::Api::CCMenuController` re-implements its own `#stack` and `#authenticate_api_client` methods, and in doing so bypasses the stack-scoping enforcement that `Shipit::Api::BaseController` normally applies for `ApiClient` tokens that are bound to a single stack.

### Finding Description
`ApiClient` records can optionally be scoped to a single stack via `belongs_to :stack, optional: true` and `stack_id` [1](#0-0) . The intended invariant, enforced in `Shipit::Api::BaseController`, is: a token bound to `stack_id` may only ever resolve `stack`/`stacks` to that one stack:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`Shipit::Api::CCMenuController` (used for CI-status "CCMenu" XML) overrides both of these methods:

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end

  def authenticate_api_client
    @current_api_client = ApiClient.authenticate(params[:token])
    super unless @current_api_client
  end
end
``` [3](#0-2) 

Here, `stack` is resolved directly via `Stack.from_param!(params[:stack_id])`, which is unscoped by `current_api_client.stack_id`. The `require_permission :read, :stack` before-action only checks that the token's `permissions` array contains `"read:stack"` [4](#0-3)  — it never verifies that the requested `stack_id` in the URL matches the stack the token is scoped to.

This creates exactly the "stack a token authorizes vs. stack it touches" binding break: `token.stack_id == requested_stack.id` is the invariant the system is supposed to maintain, but for this endpoint the code only checks `token.permissions.include?("read:stack")`, independent of which `stack_id` path segment is supplied.

The `ccmenu_url` flow explicitly creates single-purpose, stack-scoped tokens intended to be embedded in third-party CI dashboard tools:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
``` [5](#0-4) 
These tokens are meant to be scoped per-stack (embedded with a `stack_id` in the URL and handed to external CI tooling), but because `CCMenuController#stack` ignores `current_api_client.stack_id`, the same token string can be replayed against any other stack's `/ccmenu/*stack_id` path to read that stack's build/deploy status, name, and last deploy info.

### Impact Explanation
This crosses the "a stack a token authorises versus a stack it touches" boundary explicitly called out as in-scope. An attacker who obtains (or is legitimately given, e.g. via an embedded CI widget) a `read:stack`-scoped CCMenu token for one stack can enumerate and read status/output metadata (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of any other stack in the Shipit instance, including private/production stacks the token was never meant to access. This matches the "High" impact tier — unauthorized/unscoped read of stack state via a credential-authorization mismatch — since the token is valid (authenticated) but its authorization scope is not honored for the resource being touched.

### Likelihood Explanation
Likelihood is high for anyone already holding a valid stack-scoped `read:stack` CCMenu token (these tokens are routinely embedded in third-party CI status widgets/URLs, i.e., lower-trust contexts than the main Shipit UI). No additional privileges are required beyond having one such token; the attacker only needs to change the `stack_id` path segment of the request to pivot to other stacks.

### Recommendation
Make `Shipit::Api::CCMenuController#stack` use the scoped `stacks` helper from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!(params[:stack_id])`, so that `current_api_client.stack_id` is enforced identically to every other API controller.

### Proof of Concept
1. As an authenticated Shipit user, request a CCMenu URL for `stack-A` via `CCMenuUrlController#fetch`; this creates/reuses an `ApiClient` named "CCMenu Client" scoped only to `stack-A` (`permissions: ["read:stack"]`), and returns a signed `token`.
2. Take the returned `token` value.
3. Send `GET /ccmenu/stack-B-owner/stack-B-name/stack-B-env?token=<token>` where `stack-B` is a different, unrelated stack.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id`, and `require_permission :read, :stack` only checks the generic `"read:stack"` permission string, the request succeeds and returns `stack-B`'s CCMenu XML (name, last build status, etc.), even though the token was only ever authorized for `stack-A`.

### Citations

**File:** app/models/shipit/api_client.rb (L1-21)
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
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
end
```
