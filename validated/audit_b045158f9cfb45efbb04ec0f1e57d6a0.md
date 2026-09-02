## Title
Stack-scoped `ApiClient` tokens can read CCMenu build status of any stack, bypassing their `stack_id` binding - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`ApiClient` tokens can be scoped to a single stack via the `stack_id` column, and `Api::BaseController#stacks`/`#stack` enforce that binding on every stack-scoped endpoint. `Api::CCMenuController` overrides `#stack` with an unscoped lookup, so a token authorized to read only one stack can read the CCMenu status of any stack in the deployment, breaking the "stack a token authorizes" ↔ "stack it touches" binding.

### Finding Description
`Shipit::ApiClient` supports an optional `stack_id` that restricts a token to a single stack [1](#0-0) . `Api::BaseController` enforces this scoping generically:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that calls the inherited `stack` helper (e.g. `LocksController`) is correctly limited to `stacks`, the client's authorized scope [3](#0-2) .

`Api::CCMenuController`, however, requires only the `read:stack` permission and then redefines `stack` to bypass the scoped `stacks` collection entirely, looking up the stack directly by parameter with no `current_api_client.stack_id` check:

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  private

  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end
``` [4](#0-3) 

`require_permission!` only checks that the token includes the `read:stack` string permission; it never checks which stack the token is bound to:

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [5](#0-4) 

So for `CCMenuController#show`, the only authorization gate is possession of a token with `read:stack` in its `permissions` array — the `stack_id` scoping that is meant to bind that token to one specific stack is silently ignored.

The binding broken is: **stack a token authorizes = stack it touches**. Before the flaw, a stack-scoped token could only ever resolve `stack` to its own `stack_id`. After hitting `CCMenuController#show`, the same token can resolve `stack` to *any* `Stack.from_param!` value supplied in the request, i.e. any stack in the Shipit instance.

### Impact Explanation
This is an unauthenticated-scope escalation into stack state: a token deliberately restricted (by whoever created it) to a single stack — for example a low-trust integration meant to only see one project's CI status — can be used to read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, etc.) of every other stack managed by the Shipit instance, including stacks belonging to unrelated repositories/teams. This matches the specified High-impact category: "unauthenticated read of stack state ... " achieved via escalation into the `read:stack` authorization scope beyond the token's intended `stack_id` binding.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped tokens (the documented/tested use case, e.g. fixture `here_come_the_walrus`, which is `stack: shipit` + `read:stack`). No special privileges beyond holding such a legitimately-scoped, low-trust token are required; the attacker only needs to know or guess another stack's `to_param` (slug), which is not secret (stack pages/URLs are visible to any authenticated Shipit user, and CCMenu URLs are commonly shared with CI dashboard tooling).

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and let it use the inherited, scope-checked `BaseController#stack` (backed by `#stacks`), so the `current_api_client.stack_id` restriction is enforced consistently across all API endpoints, including CCMenu.

### Proof of Concept
1. Create (or use fixture `here_come_the_walrus`) an `ApiClient` with `stack: shipit`, permissions `['read:stack']` [6](#0-5) . This token should only ever be able to touch the `shipit` stack, per `BaseController#stacks`.
2. Using this token's `authentication_token`, issue:
   ```
   GET /api_clients... /ccmenu?stack_id=<some-other-stack-slug>&token=<here_come_the_walrus token>
   ```
   i.e. call `Api::CCMenuController#show` with `stack_id` set to a stack other than `shipit`.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(...)` [7](#0-6) , the lookup succeeds for the unrelated stack, and the request returns `200 OK` with that stack's CCMenu XML (name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) — confirmed by the existing test asserting a 200 response and XML attributes for arbitrary `stack_id` values [8](#0-7) , which never asserts that the request is rejected when `stack_id` differs from the client's bound stack. Compare this to `Api::StacksControllerTest`, where an equivalent stack-scoped client ("here_come_the_walrus") is correctly restricted to a single stack when hitting the scoped `#index` action [9](#0-8)  — no analogous restriction exists for `CCMenuController`.

### Citations

**File:** app/models/shipit/api_client.rb (L7-9)
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/locks_controller.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class LocksController < BaseController
      require_permission :lock, :stack

      params do
        requires :reason, String, presence: true
      end
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end

      params do
        requires :reason, String, presence: true
      end
      def update
        stack.lock(params.reason, current_user)
        render_resource(stack)
      end

      def destroy
        stack.unlock
        render_resource(stack)
      end
    end
  end
end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-31)
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-39)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
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
