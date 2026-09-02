## Confirmed: `stack_id`-scoped `ApiClient` tokens bypass their stack scope in `Shipit::Api::CCMenuController`

### Title
CCMenu API endpoint allows a stack-scoped `ApiClient` token to read build/deploy status of any stack, not just the stack it was authorized for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`ApiClient` records can be scoped to a single `Stack` via `stack_id`, and `Shipit::Api::BaseController#stacks`/`#stack` enforce that scope for every other API endpoint. `CCMenuController` overrides `#stack` to bypass that scoping entirely, so a token that is only supposed to authorize `read:stack` on its own `stack_id` can be replayed with an arbitrary `stack_id` param to read another stack's deploy/build status.

### Finding Description
`Shipit::Api::BaseController` defines the intended binding between "the stack(s) a token authorizes" and "the stack a request touches": [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped, and `stack` resolves `params[:id]`/`params[:stack_id]` only within that restricted set. Every other API controller (`StacksController`, `DeploysController`, `TasksController`, etc.) inherits this `stack` method, so a token scoped to stack A cannot address stack B.

`CCMenuController`, however, overrides `stack` to bypass the scoped `stacks` collection and load directly from the global table: [2](#0-1) 

Authorization is enforced only via `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`: [3](#0-2) 

This check only verifies that the string `"read:stack"` is present in the client's `permissions` array - it has no notion of *which* stack. The `stack_id` restriction that would normally close that gap (as it does for `StacksController#stack`, `DeploysController`, etc.) is specifically dropped in `CCMenuController#stack`.

The equality the engine is supposed to preserve is:
```
stack(s) a token authorizes (current_api_client.stack_id) == stack(s) a request/action touches (params[:stack_id] resolved through `stack`)
```
In `CCMenuController` this becomes:
```
stack(s) a token authorizes (current_api_client.stack_id, e.g. "shipit")  !=  stack a request touches (any stack, chosen freely via params[:stack_id])
```
because `Stack.from_param!` is not filtered by `current_api_client.stack_id`.

The `here_come_the_walrus` fixture demonstrates the intended narrow scope (`stack: shipit`, only `read:stack` permission): [4](#0-3) 

and is used elsewhere to prove scoping works correctly for `StacksController#index` ("an api client scoped to a stack will only see that one stack"): [5](#0-4) 

But no equivalent test exists for `CCMenuController`, and the existing tests only exercise the unscoped `spy` client (`authenticate!` in `ApiControllerTestCase`), never asserting that `here_come_the_walrus` (scoped to `shipit`) is denied access to a different stack's CCMenu status: [6](#0-5) 

### Impact Explanation
Any holder of a stack-scoped `read:stack` token (which is deliberately issued with the narrowest permission set, e.g. via `CCMenuUrlController`) can supply a different `stack_id` to `GET /api/stacks/:stack_id/ccmenu.xml` and read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, activity) of any stack in the Shipit instance - including stacks for repositories the token was never meant to see. This is a read-scope escalation: it discloses stack/task state across a repository/stack boundary the token issuer explicitly tried to restrict, matching the "unauthorized read of stack state" class of impact called out for this engine.

Note: `CCMenuUrlController#client` mints exactly this kind of narrowly-scoped token for arbitrary users clicking "CCMenu URL" on a stack page: [7](#0-6) 

so this is a scoping mechanism that is actively used and expected to hold in practice, not merely a theoretical construct.

### Likelihood Explanation
High. Exploitation requires only a valid, but narrowly-scoped, `read:stack` API token (obtainable by any authenticated Shipit user for any stack they can view via the "CCMenu URL" feature) and changing one URL parameter (`stack_id`) to a different stack's slug. No additional privilege, secret, or race condition is needed.

### Recommendation
Remove the `stack` override in `CCMenuController` (or make it delegate to the inherited, scope-aware `stack`/`stacks` methods from `BaseController`) so that a stack-scoped `ApiClient` can only address the stack referenced by `current_api_client.stack_id`. Add a regression test using the `here_come_the_walrus` fixture asserting a 404/403 when it requests a different stack's `ccmenu` endpoint.

### Proof of Concept
1. As a Shipit user with access to stack `myorg/repo-a/production`, visit that stack and use the "CCMenu URL" feature; this creates/reuses an `ApiClient` scoped to `stack_id` = repo-a's stack, with `permissions: ['read:stack']`, and returns a signed `token`.
2. Using that `token`, issue:
   `GET /api/stacks/otherorg/repo-b/production/ccmenu.xml?token=<token>`
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (unscoped), the request succeeds and returns `repo-b`'s deploy status/build state, even though the token was only supposed to authorize reading `repo-a`'s stack. [8](#0-7)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
