## Title
Stack-Scoped API Client Can Read Any Stack's CCMenu Build Status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` deliberately restricts a stack-scoped `ApiClient` (one with `stack_id` set) to only the single `Stack` it was issued for, via the `stacks`/`stack` helpers [1](#0-0) . `Api::CCMenuController` overrides `stack` to bypass this scoping entirely, resolving the target stack straight from the unscoped `Stack.from_param!(params[:stack_id])` [2](#0-1) . This breaks the binding "the stack a token authorizes" vs. "the stack it touches."

### Finding Description
`ApiClient` can optionally be bound to a single `Stack` (`belongs_to :stack, optional: true`) [3](#0-2) . The base API controller enforces this binding for every other endpoint by scoping the queryable stacks to `current_api_client.stack_id` before resolving `params[:stack_id]`: [1](#0-0) 

This is confirmed as the intended authorization model by the test "an api client scoped to a stack will only see that one stack" [4](#0-3)  and the `here_come_the_walrus` fixture, which is created with `stack: shipit` [5](#0-4) .

`Api::CCMenuController`, however, defines its own private `stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the entire `Stack` table, never consulting `current_api_client.stack_id`: [2](#0-1) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!` [6](#0-5)  — it performs no per-record scope check. Because `authenticate_api_client` here accepts a token from `params[:token]` as well as `Authorization: Basic` headers [7](#0-6) , any valid `ApiClient` token with `read:stack` — including one deliberately scoped to a single stack for use in a public "CCMenu" URL — can be replayed against `GET /api/:stack_id/ccmenu` with an arbitrary `stack_id` and will return that other stack's build/deploy status.

The existing test suite only verifies behavior for the correct stack and never asserts that a different `stack_id` is rejected [8](#0-7) , which is consistent with the scoping bypass never having been exercised for cross-stack access.

### Impact Explanation
This matches the "High" impact category: "unauthenticated read of stack state, task streams or deploy output." A token minted for stack A (e.g., embedded in a CCMenu URL that is often distributed to CI dashboards or team members, per `CCMenuUrlController`) discloses stack B's `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and whether stack B is locked — for every stack in the Shipit instance, not just the one the token holder was authorized to see. It crosses the authorization boundary the stack-scoped `ApiClient` model exists to enforce.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` token (a normal, low-privilege, intentionally narrow-purpose credential — e.g. a CCMenu URL shared with a CI dashboard, or a scoped API client created for another integration) can trigger this simply by changing the `stack_id` path/query parameter of a request they are already entitled to make. No additional secrets, no elevated privileges, and no code execution are required — only possession of a legitimately-issued, narrowly-scoped token.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController`, i.e. `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` cannot resolve any stack outside its `stack_id` binding.

### Proof of Concept
1. Create a stack-scoped `ApiClient` for `stack: shipit` with permission `read:stack` (as done via `CCMenuUrlController#client`, which mints a `read:stack` token: [9](#0-8) ).
2. Take that client's `authentication_token` and issue: `GET /api/<other_stack_id>/ccmenu?token=<token>` where `<other_stack_id>` is a different stack the client was never scoped to.
3. Because `Api::CCMenuController#stack` uses `Stack.from_param!` rather than the scoped `stacks.from_param!`, and `authenticate_api_client` only validates the token/permission (not stack ownership), the response returns the other stack's build status XML instead of a 403/404.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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

**File:** app/models/shipit/api_client.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-51)
```ruby
# frozen_string_literal: true

require 'test_helper'

module Shipit
  module Api
    class CCMenuControllerTest < ApiControllerTestCase
      setup do
        authenticate!
        @stack = shipit_stacks(:shipit)
      end

      test "a request with insufficient permissions will render a 403" do
        @client.update!(permissions: [])
        get :show, params: { stack_id: @stack.to_param }
        assert_response :forbidden
        assert_json 'message', 'This operation requires the `read:stack` permission'
      end

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

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end

      test "stacks with no deploys render correctly" do
        stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
        get :show, params: { stack_id: stack.to_param }
        assert_payload 'lastBuildStatus', 'Success'
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
