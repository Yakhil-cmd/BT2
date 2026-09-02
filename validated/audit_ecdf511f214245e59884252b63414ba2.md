### Title
Stack-scoped ApiClient tokens can read CCMenu status of any stack, bypassing token stack scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup to bypass the stack-scoping enforced by `Shipit::Api::BaseController`. A `Shipit::ApiClient` token that is scoped to a single stack (`api_client.stack_id` set) is meant to only be usable for that stack, but through this controller it can be used to read the build/deploy status of *any* stack in the installation.

### Finding Description
`Shipit::Api::BaseController` defines a scoped stack lookup: [1](#0-0) 

`current_api_client.stack_id?` restricts the resolvable stacks to the one the token was created for — this is the binding: *the stack the token authorizes == the stack it can touch*. Every other authenticated API controller (e.g. `OutputsController`, `Api::StacksController`) inherits this scoped `stack` method.

`CCMenuController`, however, defines its own `stack` method that ignores this scope entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, instead of `stacks.from_param!(params[:stack_id])`. The `require_permission :read, :stack` check only verifies that the token has the `read:stack` permission string; it does not verify the token is authorized for *this particular* stack. `ApiClient#check_permissions!` only checks the permission list, never the `stack_id`: [3](#0-2) 

As a result, a token created with `stack_id` set to stack A (e.g. via `Shipit::CCMenuUrlController#fetch`, which mints a `read:stack`-scoped `ApiClient` for a specific stack) can be replayed against `/api/stacks/:stack_id/ccmenu.xml` for stack B, and will succeed because the `stack` method never consults `current_api_client.stack_id`.

Before the attack: token T is authorized only for `stack_id == A` (equality holds: token-authorized-stack == A).
After the attack: an attacker in possession of T supplies `params[:stack_id] == B`; `CCMenuController#stack` resolves and serves stack B's data — the equality `token-authorized-stack == stack-touched` is broken.

### Impact Explanation
This grants unauthenticated-scope read access to stack state (name, activity, `lastBuildStatus`, `lastBuildLabel`, `webUrl`) for any stack in the Shipit instance, using a token that was only ever meant to be valid for one specific stack. This matches the High-impact class "unauthenticated read of stack state" relative to what the token holder was authorized for — the token's scope guarantee is broken by the engine's own routing logic, not by a missing feature elsewhere.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` API token (these tokens are handed to CI dashboards / CCMenu clients via `CCMenuUrlController`, and are also creatable generically via the admin API client management flow) can trivially exploit this by changing `stack_id` in the request URL — no special privileges beyond possessing that one token are required.

### Recommendation
Change `CCMenuController#stack` to use the scoped lookup consistent with the rest of the API surface:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it inherits the `current_api_client.stack_id?` restriction defined in `BaseController#stacks`.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to stack "shipit" with `read:stack` permission (fixture `here_come_the_walrus` demonstrates this pattern): [4](#0-3) 
2. Authenticate as that client and request another stack's CCMenu endpoint, e.g. `GET /api/stacks/rails-staging/ccmenu.xml`, using `here_come_the_walrus`'s token.
3. Compare with `Api::StacksController#index`, which correctly returns zero stacks outside the token's scope for the same client: [5](#0-4) 
4. `CCMenuController#show` will instead return `200 OK` with the other stack's build status because `stack` resolves via unscoped `Stack.from_param!`.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/stacks_controller_test.rb (L188-198)
```ruby
      test "#index returns a list of stacks filtered by repo and api client" do
        authenticate!(:here_come_the_walrus)

        repo = shipit_repositories(:soc)

        get :index, params: { repo_owner: repo.owner, repo_name: repo.name }
        assert_response :ok
        assert_json do |stacks|
          assert_equal 0, stacks.size
        end
      end
```
