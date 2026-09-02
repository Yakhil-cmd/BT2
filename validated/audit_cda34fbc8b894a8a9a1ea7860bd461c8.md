### Title
Scoped ApiClient tokens can read any stack's CCMenu/deploy status by bypassing the token's `stack_id` binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` binds an `ApiClient` token's authorization to a specific stack via `current_api_client.stack_id`, and every other API controller (`StacksController`, `TasksController`, `DeploysController`, etc.) resolves the target `stack` through this scoped helper. `Api::CCMenuController` overrides that helper to look the stack up unscoped, breaking the equality "stack a token authorises == stack it touches."

### Finding Description
`BaseController` defines the scoping that every API endpoint is supposed to rely on: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

A token created with a `stack_id` (i.e. an `ApiClient` scoped to a single stack, such as the `here_come_the_walrus` fixture) is only supposed to resolve `stack` from within `stacks`, which is filtered to `Stack.where(id: current_api_client.stack_id)`.

`Api::CCMenuController` however redefines `stack` to bypass this scoping entirely: [2](#0-1) 

```ruby
module Shipit
  module Api
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
  end
end
```

`require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)`, which merely checks that `'read:stack'` is present in the client's `permissions` array — it does not check which stack the client is scoped to: [3](#0-2) 

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
  end
  true
end
```

Consequently, an `ApiClient` created and scoped to Stack A (with `read:stack` permission) authenticates successfully for the CCMenu endpoint (via Basic Auth or `params[:token]`), passes the `read:stack` permission check, and then `stack` is resolved via `Stack.from_param!(params[:stack_id])` with **no filter tying it back to `current_api_client.stack_id`**. Supplying a different `stack_id` in the request lets the token read deploy state for any stack in the installation, not just the one it was issued for.

### Impact Explanation
This breaks the trust binding between "the stack a token authorizes" (its `stack_id` at creation) and "the stack it actually touches" (`params[:stack_id]` in the request). Per the accepted impact classes, this is an unauthorized read of stack state / deploy output: the CCMenu XML response includes the target stack's `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` (deploy status/output metadata), as validated by the controller's own tests: [4](#0-3) 

This lets a party holding a narrowly-scoped, low-privilege token (e.g. embedded in a CI dashboard config, meant to see only its own stack) enumerate and read deploy/build status of any other stack in the Shipit instance, which is explicitly listed as a High-severity impact ("unauthenticated/unauthorized read of stack state, task streams or deploy output").

### Likelihood Explanation
Likelihood is high for any deployment where multiple `ApiClient` tokens are issued scoped to different stacks (the documented/intended use of `stack_id`-bound tokens, exercised by the `here_come_the_walrus` fixture and test suite). Any holder of such a token can trivially probe other `stack_id`/`repo/branch` param values against the `/api/stacks/:stack_id/ccmenu` route to read other stacks' status — no additional secret, GitHub credential, or privileged access is required beyond the token itself, which is the normal credential this endpoint expects any caller to present.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that stack-scoped `ApiClient` tokens cannot resolve stacks outside their `stack_id` binding.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, name: 'ci', stack: stack_a, permissions: ['read:stack'])`.
2. Authenticate against `Api::CCMenuController#show` using this client's token (Basic Auth or `params[:token]`), but pass Stack B's param (`stack_id: stack_b.to_param`).
3. Observe the response returns Stack B's CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, etc.) even though the token is scoped to Stack A — confirmed by the controller code path `stack` → `Stack.from_param!(params[:stack_id])`, which never consults `current_api_client.stack_id`, unlike `BaseController#stack`/`#stacks` used by every other API controller (`Api::StacksController`, `Api::TasksController`, `Api::DeploysController`, etc.).

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
