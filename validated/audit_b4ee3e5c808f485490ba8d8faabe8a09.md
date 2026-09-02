### Title
Cross-stack authorization bypass in CCMenu API endpoint — a stack-scoped `ApiClient` token can read status for any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The `Shipit::Api::BaseController` binds an `ApiClient`'s stack scope to the stacks it is permitted to touch via its `stacks`/`stack` helper methods, but `Shipit::Api::CCMenuController` overrides `#stack` in a way that ignores that binding, letting any authenticated `ApiClient` read CCMenu status data for stacks outside its authorized scope.

### Finding Description
`Shipit::Api::BaseController` enforces the equality "stack a token authorizes == stack a request touches" through: [1](#0-0) 
`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to one stack, and `stack` (used by most API controllers, e.g. `StacksController`) resolves the requested `params[:stack_id]` only within that restricted scope.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 
It resolves `params[:stack_id]` directly against `Stack.from_param!`, the unrestricted global scope, instead of `stacks.from_param!`. The controller's only authorization check is `require_permission :read, :stack`, defined in `BaseController`: [3](#0-2) 
which only verifies the client's `permissions` array contains `read:stack` (a generic capability check via `ApiClient#check_permissions!`): [4](#0-3) 
It never checks that the requested `stack_id` matches the client's own `stack_id` (`belongs_to :stack, optional: true`): [5](#0-4) 

Root cause: the "stack a token authorizes" (the `ApiClient#stack_id` binding, enforced correctly in `BaseController#stacks`) is broken by `CCMenuController#stack`, which computes "the stack the request touches" without applying that binding — a direct instance of the equality violation the reviewer is scanning for.

### Impact Explanation
An `ApiClient` created with only `read:stack` permission and scoped to a single specific stack (a common least-privilege configuration, e.g. giving a CI dashboard integration read-only access to one project's status) can be used to enumerate and read the CCMenu XML status (build name, last build status/label/time, web URL) of **any** stack in the Shipit instance by supplying a different `stack_id` in the request — not just the stack it was provisioned for. This is an authorization-scope escalation / unauthenticated-for-other-stacks read of stack state, matching the "escalation into authorization... unauthenticated read of stack state" High-impact category, since the token holder gains read access far beyond its intended, narrowly scoped grant.

### Likelihood Explanation
Any party holding a valid `ApiClient` authentication token (even one deliberately scoped to a single stack with minimal `read:stack` permission) can trigger this by simply changing the `stack_id` query parameter — no additional privilege, secret, or race condition is required. The route is reachable via a normal authenticated `GET` request to the `ccmenu` endpoint (`app/controllers/shipit/api/ccmenu_controller.rb#show`), and the bug is a straightforward code-path bypass rather than a timing or environment-dependent condition.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped resolution from `BaseController`, i.e. `stacks.from_param!(params[:stack_id])`, instead of calling `Stack.from_param!` directly, so that `ApiClient#stack_id` scoping is uniformly enforced across all API controllers.

### Proof of Concept
1. Create two stacks, `stack_a` (private/sensitive) and `stack_b`.
2. Create an `ApiClient` scoped to `stack_b` only (`stack: stack_b`, `permissions: ['read:stack']`).
3. Authenticate with that client's token (`Basic` auth using `ApiClient#authentication_token`) and request:
   `GET /api/stacks/stack_a_id/ccmenu.xml` (or wherever `stack_id` is `stack_a`'s id/param, not `stack_b`).
4. Compare against `BaseController#stack`/`stacks` behavior: an equivalent request to `Shipit::Api::StacksController#show` for `stack_a` with the same token correctly returns `403 Forbidden` because `stacks` filters by `current_api_client.stack_id`.
5. Observe that `CCMenuController#show` instead returns `200 OK` with `stack_a`'s build status/name, because `CCMenuController#stack` (`Stack.from_param!`) never applies the `current_api_client.stack_id` filter that `BaseController#stack` (`stacks.from_param!`) applies. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L1-103)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class BaseController < ActionController::Base
      skip_before_action :verify_authenticity_token, raise: false

      include Shipit::Engine.routes.url_helpers
      include Rendering
      include Cacheable
      include Paginable

      rescue_from ApiClient::InsufficientPermission, with: :insufficient_permission
      rescue_from EnvironmentVariables::NotPermitted, with: :validation_error
      rescue_from TaskDefinition::NotFound, with: :not_found
      rescue_from Task::ConcurrentTaskRunning, with: :conflict

      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
      end

      before_action :authenticate_api_client

      def index
        render(json: { stacks_url: api_stacks_url })
      end

      private

      module BasicAuth
        # Workaround for https://github.com/rails/rails/pull/44610
        extend ActionController::HttpAuthentication::Basic
        extend self

        private

        def basic_credentials?(request)
          request.authorization.present? && (auth_scheme(request).downcase == "basic")
        end
      end

      def namespace_for_serializer
        nil
      end

      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end

      attr_reader :current_api_client

      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end

      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end

      def insufficient_permission(error)
        render(status: :forbidden, json: { message: error.message })
      end

      def validation_error(error)
        render(status: :unprocessable_entity, json: { message: error.message })
      end

      def not_found(_error)
        render(status: :not_found, json: { status: '404', error: 'Not Found' })
      end

      def conflict(error)
        render(status: :conflict, json: { status: '409', error: error.message })
      end
    end
  end
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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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
