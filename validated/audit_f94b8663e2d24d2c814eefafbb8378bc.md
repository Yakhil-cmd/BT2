### Title
Stack-scoped API token can read CI/build status of any stack, bypassing its `stack_id` scope - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides `#stack` to resolve the stack directly from the request params instead of through the scoped `stacks` relation, breaking the binding between "the stack a token authorizes" and "the stack the request actually touches."

### Finding Description
`Shipit::ApiClient` can be scoped to a single stack via its `stack_id` column, and `Shipit::Api::BaseController` is designed to enforce that scope everywhere a stack is resolved: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`current_api_client.check_permissions!` only checks the coarse `operation:scope` permission string (e.g. `read:stack`) and never checks `stack_id` at all: [2](#0-1) 

The actual `stack_id` restriction is therefore enforced solely by the `stacks` scoping helper being used when resolving `params[:stack_id]`.

`Shipit::Api::CCMenuController`, however, defines its own `#stack` method that bypasses `stacks` entirely and resolves the stack directly: [3](#0-2) 

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
```

`require_permission :read, :stack` only asserts that the token's permission list includes `"read:stack"` — it never checks whether the requested `stack_id` matches `current_api_client.stack_id`. Since `#stack` does not go through `stacks`, the scope binding (`api_client.stack_id? -> Stack.where(id: ...)`) is never applied for this controller.

The `CCMenuUrlController` legitimately issues exactly this kind of scoped, single-stack token for embedding in third-party CCMenu/CI dashboard tools: [4](#0-3) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

Such a token/URL is meant to be embedded in low-trust external tooling (CI dashboards, status widgets) scoped to one stack only. Any holder of that token — including a party who is not otherwise authorized to view other stacks — can simply change `stack_id` in the URL/query string to enumerate and read build/deploy status for every stack in the Shipit instance.

### Impact Explanation
This crosses the binding "a stack a token authorizes versus a stack it touches": the token is created and intended to authorize read access to exactly one stack, but the request path it drives (`CCMenuController#show`) touches an attacker-chosen stack. The impact is unauthenticated (relative to the target stack) read of stack/deploy state — matching the "High" impact category defined by the rules ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
Likelihood is high given the intended distribution model of these tokens: the CCMenu URL (containing the plaintext token in the query string) is designed to be handed out to third-party CI dashboard tools/widgets, which are inherently lower-trust than the Shipit UI itself. Any holder of one such URL can trivially probe other `stack_id`/`to_param` values (e.g., `owner/repo/environment` slugs, which are often predictable/enumerable) to read information about stacks they were never granted access to.

### Recommendation
Fix `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` relation (the same helper `BaseController#stack` uses), e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
More generally, `ApiClient#check_permissions!` (or a dedicated check) should also validate `stack_id` scope centrally so that any future controller cannot silently reintroduce this bypass by defining a custom, unscoped `#stack`/`#stacks` method.

### Proof of Concept
1. As a user with access to Stack A, visit Stack A's settings page to trigger `CCMenuUrlController#fetch`, which creates (or reuses) an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` and returns a URL like `.../api/stacks/<stack_A_id>/ccmenu.xml?token=<TOKEN>`. [5](#0-4) 
2. Take that `TOKEN` and issue a request to a different stack: `GET /api/stacks/<stack_B_to_param>/ccmenu.xml?token=<TOKEN>`.
3. `authenticate_api_client` in `CCMenuController` authenticates the token successfully (it's a valid `ApiClient`), `require_permission :read, :stack` passes because the token has `"read:stack"` in its permission list, and `#stack` resolves Stack B directly via `Stack.from_param!(params[:stack_id])` without any `stack_id` check. [6](#0-5) 
4. The response renders Stack B's CI/build/deploy status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`), even though the token was only ever authorized for Stack A. [7](#0-6)

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
