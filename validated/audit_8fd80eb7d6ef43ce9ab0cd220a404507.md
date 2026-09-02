### Title
Stack-scoped API tokens can read CI/build status of any stack via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the `stack` lookup helper in a way that bypasses the per-`ApiClient` stack scoping enforced by `Api::BaseController`. An `ApiClient` token that is supposed to be restricted to a single stack (`ApiClient#stack_id`) can be replayed with a different `stack_id` in the URL to read CI/build state for stacks it was never authorized to access.

### Finding Description
`Api::BaseController` implements per-token stack scoping through two cooperating methods: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

If an `ApiClient` record has a non-nil `stack_id` (i.e. it was created scoped to one stack, as with the `here_come_the_walrus` fixture, which has only `read:stack` permission and `stack: shipit`), any controller relying on the inherited `stack` helper will raise `ActiveRecord::RecordNotFound` when the client requests a `stack_id` different from the one it's bound to. [2](#0-1) 

However, `Api::CCMenuController` completely reimplements `stack` and `authenticate_api_client`, dropping the scoping check entirely: [3](#0-2) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`require_permission :read, :stack` only checks that the token has the string permission `read:stack` in its `permissions` list; it never checks `current_api_client.stack_id`: [4](#0-3) 

Because `Stack.from_param!(params[:stack_id])` here queries `Stack` directly instead of the scoped `stacks` relation, any stack-scoped token with `read:stack` permission can be presented against `GET /api/stacks/*stack_id/ccmenu` with an arbitrary `stack_id`, and the controller will happily render CI/build status for that unrelated stack.

This breaks the binding the token is supposed to enforce: **stack a token authorizes ≠ stack the token can touch**. Before the mismatch, a scoped token can only read the one stack recorded in `ApiClient#stack_id` (as enforced everywhere else, e.g. `Api::StacksController#index`, see [5](#0-4) ). After hitting the CCMenu endpoint, the same token can read any stack in the installation.

### Impact Explanation
This is an unauthenticated-boundary-crossing read: a caller in possession of a legitimately-issued, narrowly-scoped `ApiClient` token (e.g., one generated for a single low-sensitivity stack via `CCMenuUrlController`, or any other stack-scoped client) can enumerate and read the build/CI status (`name`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state, etc.) of every other stack managed by the Shipit instance, including stacks belonging to other repositories/teams that the token was never granted access to. This matches the "unauthenticated read of stack state" High-impact category described for authorization/scope escalation issues, since it escalates a single-stack-scoped credential into an all-stacks read credential.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (which by design is meant to have minimal exposure, e.g., a per-stack CCMenu credential embedded in a CI dashboard tool) can trivially exploit this by changing the `stack_id` path segment of the request URL — no additional privileges, secrets, or social engineering are required.

### Recommendation
Make `Api::CCMenuController#stack` use the same scoped `stacks` relation as `Api::BaseController`, i.e. remove the override (or reimplement it as `stacks.from_param!(params[:stack_id])`) so requests for stacks outside of `current_api_client.stack_id` are rejected with 404, consistent with every other API controller.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id = A` with `permissions: ['read:stack']` (e.g., the `here_come_the_walrus` fixture, scoped to the `shipit` stack).
2. Using that client's `authentication_token`, issue:
   `GET /api/stacks/<other-owner>/<other-repo>/<other-env>/ccmenu?token=<token>`
   for a stack `B` that the token is not scoped to.
3. Observe the request succeeds (HTTP 200) and returns `B`'s CCMenu XML (name, lastBuildStatus, lastBuildLabel, webUrl), even though the same token against `Api::StacksController#show` for stack `B` would be rejected via `stacks.from_param!` raising `RecordNotFound`.

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
