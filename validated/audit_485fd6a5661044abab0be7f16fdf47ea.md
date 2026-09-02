### Title
CCMenu API endpoint bypasses ApiClient stack-scoping, allowing a token authorized for one stack to read the deploy state of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution method used by `Shipit::Api::BaseController`, dropping the scoping that restricts a stack-bound `ApiClient` to its own `stack_id`. Any valid `ApiClient` token with `read:stack` permission — even one explicitly scoped to a single stack — can be used to read the deploy/build status of every other stack in the instance through the CCMenu XML endpoint.

### Finding Description
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . This scoping is enforced centrally in `Api::BaseController`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that inherits `stack` from `BaseController` therefore respects the `stack_id` binding on the `ApiClient` — this is the "stack a token authorises" side of the equality. However, `Shipit::Api::CCMenuController` redefines `stack` to bypass this scoping entirely:

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
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
``` [3](#0-2) 

`require_permission :read, :stack` only checks that the client's `permissions` array contains `'read:stack'` via `ApiClient#check_permissions!`:

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [4](#0-3) 

It never checks that the requested `stack_id` matches `current_api_client.stack_id`. Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of going through the scoped `stacks` collection, any `stack_id` supplied in the request is resolved — the "stack the token touches" side of the equality is now unconstrained by the token's own `stack_id` binding.

### Impact Explanation
An `ApiClient` created and scoped to a single stack (e.g. fixture `here_come_the_walrus`, scoped to stack `shipit`, permission `read:stack` only, as used and asserted in `test/controllers/api/stacks_controller_test.rb` — "an api client scoped to a stack will only see that one stack") [5](#0-4)  can nonetheless call `GET /api/stacks/:stack_id/ccmenu.xml?token=<its token>` with an arbitrary `stack_id` belonging to a different stack, and receive that stack's latest deploy/rollback status (build state, timestamps) rendered in `app/views/shipit/ccmenu/project.xml.builder`. This is an unauthorized read of stack state for a stack the token was never authorized to access, matching the "escalation ... unauthenticated read of stack state" impact bucket — the token escalates its effective scope from one stack to all stacks in the Shipit instance.

### Likelihood Explanation
Likelihood is high for anyone who already legitimately possesses one narrowly-scoped `ApiClient` token (a capability any onboarded Shipit user can self-provision through the UI, e.g. via `CCMenuUrlController#client`, `ApiClientsController#create`) [6](#0-5) . No secret, GitHub credential, or additional privilege is required beyond the token itself; only knowledge of another stack's `stack_id`/slug (visible in the UI to any authenticated user) is needed.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve the stack through the scoped `stacks` collection (i.e., remove the override, or reimplement it as `stacks.from_param!(params[:stack_id])`) so that stack-scoped `ApiClient` tokens cannot read data outside their authorized `stack_id`.

### Proof of Concept
1. As any onboarded user, create (or use the auto-created CCMenu) `ApiClient` scoped to `stack_id = A` with permission `read:stack` (matches fixture `here_come_the_walrus`, scoped to stack `shipit`).
2. Confirm the token is properly scoped: `GET /api/stacks/B` with this token returns `403`/empty result because `Api::BaseController#stacks` restricts to stack `A` only.
3. Call `GET /api/stacks/B/ccmenu.xml?token=<token>` (routed to `Shipit::Api::CCMenuController#show`).
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than the scoped `stacks` collection, the request succeeds and returns stack `B`'s latest deploy status in the XML response — despite the token only being authorized for stack `A`.

### Citations

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
