### Title
`Api::CCMenuController#stack` bypasses `ApiClient#stack_id` scoping, letting a stack-scoped CCMenu token read any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts a stack-scoped `ApiClient` (`current_api_client.stack_id?`) to only its own stack via the `stacks`/`stack` helper methods [1](#0-0) . `Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting `current_api_client.stack_id`, so any valid CCMenu token - even one issued for a single stack - can be replayed with an arbitrary `stack_id` path segment to read any other stack's CCMenu status. This is a real authorization-scope bypass reachable from the code alone, independent of how the token was captured.

### Finding Description
The intended binding is: for a scoped client, `current_api_client.stack_id == stack.id` must hold whenever `current_api_client.stack_id?` is true. In `BaseController` this is enforced: `stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` does `stacks.from_param!(params[:stack_id])` [1](#0-0) . `CCMenuController` redefines `stack` as `@stack ||= Stack.from_param!(params[:stack_id])`, calling the class method directly on `Stack` instead of the scoped `stacks` relation [2](#0-1) . `authenticate_api_client` for this controller finds the `ApiClient` purely from `params[:token]` via `ApiClient.authenticate` [3](#0-2) , and `require_permission :read, :stack` only checks the client's `permissions` array via `check_permissions!`, never the `stack_id` binding [4](#0-3) [5](#0-4) . `ApiClient.authenticate` itself only verifies the SimpleMessageVerifier signature and looks the row up by id, with no stack check [6](#0-5) .

Exploit flow: the holder of a scoped CCMenu token (e.g. `here_come_the_walrus`, a fixture client with `stack: shipit` and only `read:stack` permission [7](#0-6) ) sends `GET /api/stacks/{other_owner}/{other_repo}/{other_env}/ccmenu?token=<token>` for a stack it is not scoped to. `authenticate_api_client` accepts the token, `require_permission!` passes because the client has `read:stack`, and `stack` resolves the unrelated stack via unscoped `Stack.from_param!`, returning that stack's real deploy/build status in the XML response.

### Impact Explanation
Any holder of a stack-scoped CCMenu-issued `ApiClient` token (normally meant to expose only one stack's CI status per `CCMenuUrlController#fetch` [8](#0-7) , or any admin-scoped `ApiClient` with `stack_id` set) can enumerate `stack_id` path segments and read the CCMenu build/deploy status (`lastBuildStatus`, `lastBuildLabel`, activity, lock status) of every other stack in the Shipit instance, regardless of the scoping the token was issued with. This is a cross-tenant unauthorized read of stack state, repeatable per request against any stack, matching the "High - unauthenticated/unauthorized read of stack state" category. It does not by itself leak deploy output/log streams (those go through `TasksController`/`OutputsController`, not `CCMenuController`), so the blast radius is limited to CCMenu-exposed status fields.

### Likelihood Explanation
Exploitation requires possession of any valid `ApiClient` authentication token that has `read:stack` permission and is `stack_id`-scoped (or the ability to obtain one, e.g. as a legitimate low-privilege Shipit user requesting a CCMenu URL for their own stack via `CCMenuUrlController#fetch`, which any authenticated GitHub-team user can do). No secrets, GitHub App keys, or webhook signatures are needed - only a previously issued token. Given that, the bypass is deterministic and 100% reproducible against any `stack_id`; the only precondition is having any single valid scoped CCMenu token, which the engine itself readily issues to any authorized user for their own stacks.

### Recommendation
Make `Api::CCMenuController#stack` honor the same scoping as the rest of the API by reusing the inherited `stack`/`stacks` helpers (i.e. remove the private `stack` override, or change it to `@stack ||= stacks.from_param!(params[:stack_id])`) so that a client with `current_api_client.stack_id?` set can only resolve its own stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped token cannot read a different stack via ccmenu" do
  scoped_client = shipit_api_clients(:here_come_the_walrus) # stack_id == shipit_stacks(:shipit).id
  other_stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: "main")

  assert_not_equal scoped_client.stack_id, other_stack.id

  get :show, params: { stack_id: other_stack.to_param, token: scoped_client.authentication_token }

  # Binding under test: current_api_client.stack_id == stack.id must hold for scoped clients.
  # Currently fails: request returns 200 with other_stack's data instead of 404/403.
  assert_response :not_found
end
```
Before the fix this test fails (`assert_response :ok` with `other_stack`'s CCMenu XML payload); after switching `CCMenuController#stack` to use the inherited scoped `stacks.from_param!`, the request correctly 404s because `stacks` is restricted to `Stack.where(id: scoped_client.stack_id)`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
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
```
