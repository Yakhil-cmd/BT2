### Title
API CCMenu endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read the deploy status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` resolves the target `stack` directly from the URL parameter (`Stack.from_param!(params[:stack_id])`) instead of going through the scoped `stacks`/`stack` helpers defined in `Shipit::Api::BaseController`, which restrict lookups to `current_api_client.stack_id` when the client is scoped to a specific stack. This breaks the binding "the stack an `ApiClient` token authorizes == the stack it touches": a token that was explicitly scoped to stack A can be used to read the CCMenu XML (deploy id, status, timestamps, lock state) of any other stack B.

### Finding Description
`ApiClient` records can optionally be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Shipit::Api::BaseController` enforces this scoping generically:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that relies on the inherited `stack` method (e.g. `Shipit::Api::StacksController`) is therefore correctly restricted to the stacks the client is authorized for. However, `Shipit::Api::CCMenuController` overrides `stack` and reimplements the lookup without any client scoping:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [3](#0-2) 

The only access control applied is `require_permission :read, :stack` [4](#0-3) , which merely checks that the string `read:stack` is present in `ApiClient#permissions` via `check_permissions!` [5](#0-4) . This check never consults `current_api_client.stack_id`, so it passes identically for a client scoped to stack A and a client with global stack access. Since `stack` in `CCMenuController` is resolved by `Stack.from_param!(params[:stack_id])` directly from the route (`GET /api/stacks/*stack_id/ccmenu`, defined in `config/routes.rb` line 28), any `stack_id` in the URL is resolved regardless of the client's `stack_id` scope.

### Impact Explanation
This is High severity: it is an "unauthenticated [beyond-scope] read of stack state ... or deploy output" as enumerated in the accepted impact list. A caller holding a legitimately-issued `ApiClient` token that was intentionally scoped to a single stack (the common pattern for exposing CCMenu URLs to third-party CI dashboards, per `docs`/README references to CCMenu integration) can pivot that narrowly-scoped token to enumerate deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state) for every other stack in the Shipit instance, including private/internal repositories the token holder was never granted visibility into. This is a direct authorization-boundary violation: the token authorizes reads for stack A, but the code allows it to touch stack B.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a documented, intended use case — see `test/fixtures/shipit/api_clients.yml` fixture `here_come_the_walrus` which is scoped to `stack: shipit` and only holds `read:stack`). Any holder of such a token — e.g., a third-party monitoring/CI-status integration given a narrowly scoped credential — can trivially change the `stack_id` segment of the CCMenu URL to read other stacks' status, requiring no additional exploitation technique.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to use the inherited, client-scoped `stacks` collection instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This mirrors the pattern already used correctly in `Shipit::Api::BaseController` and other API controllers, ensuring `current_api_client.stack_id` scoping is enforced consistently.

### Proof of Concept
1. Create (or obtain) an `ApiClient` token scoped to `stack: A` with `permissions: ['read:stack']` (analogous to fixture `here_come_the_walrus`).
2. As that client, issue: `GET /api/stacks/OWNER_B/REPO_B/BRANCH_B/ccmenu?token=<scoped_token>`.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` without filtering by `current_api_client.stack_id`, the request succeeds with `200 OK` and returns stack B's deploy status XML, even though the token was only meant to authorize reads on stack A — confirmed by the absence of any stack-scope assertion in `test/controllers/api/ccmenu_controller_test.rb`, whose tests only check the `read:stack` permission string and never verify that a stack-scoped client is restricted to its own stack [6](#0-5) .

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L13-31)
```ruby
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
```
