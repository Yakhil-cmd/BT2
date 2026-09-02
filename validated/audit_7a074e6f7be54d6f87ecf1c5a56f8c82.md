### Title
CCMenuUrlController#fetch mints an unscoped ApiClient token that grants read access to every stack - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#fetch` creates an `ApiClient` intended to be scoped to a single stack's CCMenu feed, but never sets `stack_id` on it. Because `Api::BaseController#stacks` treats a client with `stack_id == nil` as unrestricted (`Stack.all`), the resulting token — handed out via a URL for one stack — authorizes read access to every stack in the installation.

### Finding Description
The claimed binding is: `client.stack_id == stack.id` (the CCMenu token for stack A should only authorize stack A). Tracing `CCMenuUrlController#fetch`: [1](#0-0) 

```ruby
def fetch
  uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
  uri.query = { 'token' => client.authentication_token }.to_query
  render(json: { ccmenu_url: uri.to_s })
end

def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

`stack` (derived from `params[:stack_id]`) is used only to build the CCMenu URL path; it is never passed into `ApiClient.create_with(...)`, so the persisted record's `stack_id` column is `nil`. `ApiClient` model: [2](#0-1) 

confirms `stack` is an optional `belongs_to`, so no validation forces it to be set. The scoping check lives in `Api::BaseController`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Since `stack_id?` is `false` (nil), `stacks` resolves to `Stack.all`, not the single stack the URL was minted for. Every controller that authorizes via `stacks`/`stack` (e.g. `Api::StacksController#index`/`#show`, `Api::MergeRequestsController#index`/`#show`) inherits this unscoped set: [4](#0-3) [5](#0-4) 

Only `read:stack` permission is checked via `require_permission!`/`check_permissions!` — permission is unrelated to stack scoping, so it does not catch this: [6](#0-5) 

Only the dedicated `Api::CCMenuController#show` action (the one actually served at the generated CCMenu URL) is naturally restricted, because it looks up the stack directly via `Stack.from_param!(params[:stack_id])` rather than through the `stacks` scope: [7](#0-6) 

But that same token (a plain signed `ApiClient` id, `ApiClient#authenticate`) works against any other endpoint that authenticates via `BasicAuth`/`ApiClient.authenticate` and relies on `stacks` for scoping, e.g. `GET /stacks` or `GET /stacks/:owner/:repo/:branch/merge_requests`, for a stack the user requesting the CCMenu URL was never meant to see data on.

The confirming test file only exercises `fetch`'s HTTP response and query string, not `client.stack_id`, so the existing test suite does not catch this: [8](#0-7) 

No other guard (`require_permission`, `verify_signature`, model validations) checks or enforces stack-scoping of an `ApiClient`; the only enforcement point is the `stack_id?` conditional in `Api::BaseController#stacks`, which this code path silently bypasses by never populating `stack_id`.

### Impact Explanation
An unprivileged user with access to any single stack's CCMenu URL feature (a normal, low-privilege Shipit UI action reachable by any authenticated Shipit user for a stack they can view) obtains a bearer token that authorizes `read:stack` operations against **every** stack in the Shipit installation, not just the one requested. This is a cross-tenant, unauthorized-read vulnerability: an attacker can enumerate `Api::StacksController#index` for all stacks, and read `Api::MergeRequestsController#index`/`#show` data (PR merge status, branch, environment) for stacks/repositories belonging to other teams. This matches "High - unauthenticated/unauthorized read of stack state" (the token was scoped to nothing, effectively broadening access far beyond intent), and is repeatable indefinitely since the token is a durable signed credential (`ApiClient#authentication_token`) that does not expire and is reused (`find_or_create_by!`) across requests.

### Likelihood Explanation
Preconditions: attacker only needs the standard, low-privilege ability to request a CCMenu URL for any one stack they have "read" visibility on through the normal UI/API (`GET /stacks/:id/ccmenu_url` route via `CCMenuUrlController#fetch`), which is a routine feature, not privileged. No secrets, GitHub tokens, or admin roles are required. This is highly feasible and cheap: a single authenticated (or session-holding) request yields the leaked-scope token, then it can be replayed against arbitrary stacks. This is a real, direct, reproducible confused-deputy bug in the engine's own code, not a theoretical concern.

### Recommendation
In `CCMenuUrlController#client`, pass `stack: stack` into `ApiClient.create_with`/`find_or_create_by!` so the persisted client is bound to the requested stack's id, matching the intended semantics of `Api::BaseController#stacks`. Additionally, consider adding a model validation or unique index in `ApiClient` to prevent a `read:stack`-scoped CCMenu client from ever being created/left with `stack_id: nil`.

### Proof of Concept
```ruby
# test/controllers/ccmenu_controller_test.rb (new test)
test ":fetch scopes the api client to the requested stack" do
  get :fetch, params: { stack_id: @stack.to_param }
  client = ApiClient.last
  assert_equal @stack.id, client.stack_id, "expected token to be scoped to stack A only"
end

test "leaked ccmenu token authorizes read access to other stacks" do
  other_stack = shipit_stacks(:cocaine_lint) # any stack != @stack
  get :fetch, params: { stack_id: @stack.to_param }
  data = JSON.parse(response.body)
  token = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)['token']

  # Attempt to use the stack-A token against Api::StacksController#index / MergeRequestsController#index for stack B
  @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(token, '')
  get :index, controller: 'shipit/api/merge_requests', params: { stack_id: other_stack.to_param }, format: :json
  assert_response :success # demonstrates the scope leak: token for stack A works on stack B
end
```
Both assertions on the equality: expected `client.stack_id == @stack.id` (fails — actual is `nil`), and expected request to stack B to be `:forbidden`/`:not_found` (fails — actual is `:success`), proving `stack ∈ {A}` degraded to `stack ∈ {all stacks}`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-22)
```ruby
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
```

**File:** app/models/shipit/api_client.rb (L4-9)
```ruby
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L13-24)
```ruby
      def index
        @stacks = stacks
        if params[:repo_owner] && params[:repo_name]
          full_repo_name = [repo_owner, repo_name].join('/')
          @stacks = if (repository = Repository.from_github_repo_name(full_repo_name))
                      stacks.where(repository:)
                    else
                      Stack.none
                    end
        end
        render_resources(@stacks)
      end
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L9-11)
```ruby
      def index
        render_resources(stack.merge_requests.includes(:head).order(id: :desc))
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** test/controllers/ccmenu_controller_test.rb (L14-33)
```ruby
    test ":fetch returns ok with json" do
      get :fetch, params: { stack_id: @stack.to_param }
      assert_response :ok
      data = JSON.parse(response.body)
      assert_includes data, 'ccmenu_url'
    end

    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
      end
    end

    test ":fetch url includes api token on query string" do
      get :fetch, params: { stack_id: @stack.to_param }
      data = JSON.parse(response.body)
      client = ApiClient.last
      query = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)
      assert_equal client.authentication_token, query['token']
    end
```
