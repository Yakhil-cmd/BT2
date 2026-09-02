### Title
Stack-scoped API tokens bypass stack authorization in the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via its `stack_id` column, and `Api::BaseController` enforces this scope by resolving the target stack through a scoped relation. `Api::CCMenuController` overrides the stack resolution method and looks the stack up unscoped, so any valid API token — even one explicitly authorized only for stack A — can read the CI/build status of any other stack B.

### Finding Description
`Api::BaseController` defines the authorization binding between a token and the stacks it may touch: [1](#0-0) 

`stacks` is restricted to `current_api_client.stack_id` when the client has one, and `stack` is resolved through that scoped relation, so a stack-scoped `ApiClient` can never resolve a `stack_id` param that isn't its own (`ActiveRecord::RecordNotFound` otherwise). This scoping is a real, tested access-control property of `ApiClient`, confirmed by `here_come_the_walrus` in [2](#0-1)  and by the assertion in [3](#0-2) .

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [4](#0-3) 

It calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(...)`, and only checks `require_permission :read, :stack` (a coarse-grained permission-name check performed by `ApiClient#check_permissions!`): [5](#0-4) 

`check_permissions!` only verifies the string `"read:stack"` is present in the client's `permissions` array — it never compares against `stack_id`. Because the CCMenu route accepts an arbitrary `stack_id` path segment (`scope '/stacks/*stack_id' ... get '/ccmenu' => 'ccmenu#show'`), an attacker holding *any* token with `read:stack` permission — including one that was granted/scoped to a single specific stack — can substitute a different `stack_id` in the URL and successfully load that other stack's CCMenu XML.

This breaks exactly the "stack a token authorizes vs. stack it touches" binding: before the request, `token.stack_id == A` and the token is only supposed to touch stack A; after hitting `/api/stacks/B/ccmenu`, the same token is used to read stack B's data because the controller's `stack` finder ignores the `stack_id` restriction that every other API endpoint enforces.

### Impact Explanation
This grants unauthorized read access to another stack's deploy/build state (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock state — see `app/views/shipit/ccmenu/project` rendered fields exercised in [6](#0-5) ) using a token that was never authorized for that stack, effectively an authorization-scope escalation across stacks/repositories within the same Shipit installation.

### Likelihood Explanation
Any holder of a valid, low-privilege, stack-scoped `read:stack` API token — the kind of credential explicitly designed to be handed out narrowly (e.g., embedded in CI-status widgets) — can trigger this simply by changing the `stack_id` segment of the URL. No elevated privileges, signing keys, or session state are required beyond the token itself.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (and the standalone `authenticate_api_client` override, or make it also enforce scoping) so it resolves the stack through the scoped `stacks` relation from `Api::BaseController`, consistent with every other API controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to stack A: `stack_id: A.id`, `permissions: ['read:stack']`.
2. As that client, request `GET /api/stacks/<A>/ccmenu` with `?token=<token>` — succeeds as expected.
3. Request `GET /api/stacks/<B>/ccmenu?token=<token>` for an unrelated stack B — succeeds and returns B's build/deploy status, even though the token's `stack_id` is A, because `Api::CCMenuController#stack` bypasses the `stacks` scoping used everywhere else (compare with `Api::StacksController#show` at `/api/stacks/<B>` using the same token, which returns `404 Not Found`).

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
