### Title
Stack-scoped ApiClient tokens can read the CCMenu status of any stack, bypassing the token's stack binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method inherited from `Shipit::Api::BaseController` in a way that skips the stack-scoping check that binds an `ApiClient`'s authorized stack to the stack it can actually act on.

### Finding Description
`BaseController` defines the correct binding between an authenticated `ApiClient` and the stack it is allowed to touch: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted set. This is the intended equality: `ApiClient.stack_id == stack.id` for any scoped client.

`CCMenuController`, however, overrides `stack` and bypasses `stacks` entirely, resolving the parameter directly against all stacks: [2](#0-1) 

The controller still enforces the generic `require_permission :read, :stack` check [3](#0-2) , which only calls `current_api_client.check_permissions!(operation, scope)` — a string permission check with no reference to which stack is being accessed [4](#0-3) . It never re-applies the `stack_id?` restriction that `BaseController#stacks` enforces for every other API endpoint (stacks, tasks, deploys, lock, hooks, merge_requests, etc., all mounted under `scope '/stacks/*stack_id'` in `config/routes.rb`, lines 27-44, and the CCMenu route at line 28).

Fixture data confirms stack-scoped clients exist in this engine by design, e.g. `here_come_the_walrus` is scoped to the `shipit` stack with only `read:stack`: [5](#0-4) .

**Binding broken:** `ApiClient.stack_id` (the stack the token is authorized for) ≠ the `stack` object the CCMenu action actually touches. Before the request, `stacks == Stack.where(id: current_api_client.stack_id)`; in `CCMenuController#stack` this becomes `Stack.from_param!(params[:stack_id])` over `Stack.all`, i.e. any stack in the installation.

### Impact Explanation
A holder of a stack-scoped `read:stack` `ApiClient` token (e.g. one created via `CCMenuUrlController`, or any credential with `read:stack` limited to one stack) can call `GET /api/stacks/:other_stack_id/ccmenu` with a different `stack_id` and receive that other stack's CCMenu XML, exposing its `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, lock state, and `webUrl` — [6](#0-5) . This is an unauthenticated-for-that-stack read of stack/deploy state across a boundary the token was never granted, matching the High-impact class "escalation into authorization... unauthenticated read of stack state... deploy output."

### Likelihood Explanation
Any party already possessing a legitimately-issued, narrowly stack-scoped API token (a routine, low-privilege credential type explicitly supported by this engine, e.g. via the CCMenu URL feature) can trigger this with a single unauthenticated-boundary-crossing GET request by supplying an arbitrary `stack_id`; no additional secret or race condition is required.

### Recommendation
Have `CCMenuController#stack` reuse the inherited, correctly-scoped `stacks`/`stack` helpers from `BaseController` instead of calling `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so the `ApiClient.stack_id` restriction is enforced consistently with every other API endpoint.

### Proof of Concept
1. Create (or reuse) an `ApiClient` scoped to stack `A` with only `read:stack` permission (matches fixture `here_come_the_walrus`, scoped to `shipit`).
2. Authenticate as this client and request `GET /api/stacks/<owner>/<repo>/<other-env-B>/ccmenu` where `B` is a stack the client was never scoped to.
3. `CCMenuController#stack` resolves `B` via `Stack.from_param!` (unscoped), `require_permission :read, :stack` passes because it only checks the string permission `read:stack`, and the response renders `B`'s deploy/build status — data the token was never authorized to access.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-45)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end
```
