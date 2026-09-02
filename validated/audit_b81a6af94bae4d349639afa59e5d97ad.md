### Title
API-scoped read-only tokens can read CI status of any stack, bypassing the token's `stack_id` scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the stack-lookup method used by every other API controller and, in doing so, drops the enforcement that binds an `ApiClient`'s authorized stack (`current_api_client.stack_id`) to the stack it is allowed to act on. Any stack-scoped, read-only token can be used to read CI/build status data for *any* stack on the instance, not just the one it was issued for.

### Finding Description
Every other API controller resolves the target stack through `Shipit::Api::BaseController#stack`, which is deliberately scoped to the calling `ApiClient`: [1](#0-0) 

```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This is the intended binding: *token's authorized stack == stack acted upon*. `CCMenuController`, however, overrides `#stack` and resolves the record directly from the global `Stack` table, completely bypassing the `stacks` scoping helper: [2](#0-1) 

```
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
  ...
end
```

`require_permission :read, :stack` only checks that the token has the `read:stack` permission string (via `ApiClient#check_permissions!`) — it never checks that `params[:stack_id]` matches `current_api_client.stack_id`: [3](#0-2) 

Any authenticated Shipit user can self-issue a stack-scoped, read-only `ApiClient` for a stack they have UI access to via the non-API CCMenu controller, which explicitly creates such a token: [4](#0-3) 

That token is meant to be usable only for the one stack it was scoped to (as enforced everywhere else, e.g. `Api::StacksController`, whose tests confirm `stack_id` scoping restricts visibility to a single stack): [5](#0-4) 

But because `Api::CCMenuController#stack` ignores `current_api_client.stack_id`, the same token can be replayed with an arbitrary `stack_id` param to read another stack's build name, activity, last build status/label and web URL: [6](#0-5) 

### Impact Explanation
This breaks the equality `stack authorized by token == stack the endpoint touches`, one of the explicitly called-out binding classes. The consequence is unauthorized cross-stack disclosure of CI/deploy state (build status, last build label, activity, target URL) for every stack in the Shipit installation, using a token that was only ever meant to be scoped to one stack. This matches the High-impact bucket: "escalation into … unauthenticated read of stack state, task streams or deploy output" (here, escalation of a properly-scoped token into a globally-readable one).

### Likelihood Explanation
Any authenticated, unprivileged Shipit user can obtain a scoped read-only `ApiClient` for a stack they legitimately have access to (through the standard `CCMenuController#fetch` flow), then simply substitute a different `stack_id` in the API request. No elevated privileges, GitHub App secrets, or webhook access are required — only a normal user session used once to mint the scoped token, after which the vulnerability itself requires no further privilege.

### Recommendation
Make `Api::CCMenuController#stack` reuse the scoped `stacks`/`stack` resolution from `BaseController` instead of querying `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the invariant that a token can only touch the stack(s) it is authorized for.

### Proof of Concept
1. As any authenticated Shipit user with access to `stack-A`, call the UI endpoint that creates a scoped read-only token (`Shipit::CcmenuController#fetch`) for `stack-A`; capture the returned `ApiClient#authentication_token`.
2. Using that token, call `GET /api/stacks/stack-B/ccmenu.xml` (a stack the user/token was never scoped to).
3. Observe that `Api::CCMenuController#stack` resolves `stack-B` via `Stack.from_param!`, ignoring the token's `stack_id`, and returns `stack-B`'s CI status — demonstrating the token-to-stack binding is not enforced on this endpoint, unlike `Api::StacksController` and other API resources.

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

**File:** test/controllers/ccmenu_controller_test.rb (L21-25)
```ruby
    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-39)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end
```
