## Analysis

`Shipit::ApiClient` supports being scoped to a single stack via its `stack_id` column [1](#0-0) . The generic `Api::BaseController` enforces this binding by scoping the `stacks` relation to that stack before resolving `params[:stack_id]`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every other API controller (e.g. `Api::StacksController`) relies on this scoped `stack`/`stacks` helper, so a token that only "authorizes" one stack can never "touch" another one.

`Api::CCMenuController`, however, overrides `stack` to bypass the scoping entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

It only checks `require_permission :read, :stack` [4](#0-3) , which merely verifies the `read:stack` permission string is present on the token — it never re-applies the `current_api_client.stack_id` restriction. This breaks the equality the base controller otherwise guarantees: `stack token authorises == stack it touches`.

### Title
Authorization bypass in `Api::CCMenuController` allows a stack-scoped API token to read any stack's state - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` resolves `params[:stack_id]` directly against `Stack.from_param!` instead of the scoped `stacks` helper used everywhere else in the API, so an `ApiClient` restricted to a single stack can read the build/deploy status of any other stack in the installation.

### Finding Description
`ApiClient` records can be created with a `stack_id`, intended to restrict that token to operate only on the associated stack [5](#0-4) . `Api::BaseController#stacks` enforces this by filtering `Stack.where(id: current_api_client.stack_id)` whenever the client is stack-scoped, and `#stack` resolves the `:stack_id` param against that filtered relation [2](#0-1) .

`Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` on the unscoped `Stack` model, entirely skipping the `current_api_client.stack_id` restriction [3](#0-2) . The only remaining guard is `require_permission :read, :stack`, which just checks that the string `"read:stack"` is present in `ApiClient#permissions` — a check that is independent of `stack_id` scoping [6](#0-5) .

Authentication for this controller also accepts the token via a plain query-string parameter rather than only Basic auth: `ApiClient.authenticate(params[:token])` [7](#0-6) , which is how such tokens are typically distributed to CI dashboards (e.g. CCTray URLs), increasing the chance the token leaks to a party who is only supposed to see one stack.

The equality broken: `stack the token authorizes` (its bound `stack_id`) vs. `stack the token's request actually touches` (any `params[:stack_id]` supplied by the caller).

### Impact Explanation
A holder of a stack-scoped API token (e.g. a CI system or a partner integration meant to see only its own stack's build status) can enumerate/read `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl` and activity for any other stack in the Shipit instance, including stacks belonging to other repositories/teams they have no authorization for. This is an unauthorized read of stack state across a trust boundary that the rest of the API deliberately enforces.

### Likelihood Explanation
Exploitation only requires possession of any valid `read:stack`-permissioned `ApiClient` token that is scoped to a stack (a normal, documented configuration for restricting third-party integrations), and knowledge/guessing of another stack's `to_param` (slug), which is not secret. No privileged access beyond the intentionally-limited token is required.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped helper, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private override entirely so it inherits `Api::BaseController#stack`/`#stacks`, restoring the `stack_id` scoping for stack-restricted API clients.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A only, with permission `read:stack` (mirrors fixture `here_come_the_walrus`) [8](#0-7) .
2. Using that client's `authentication_token`, request `GET /api/stacks/:stack_b_id/ccmenu.xml?token=<token>` for Stack B (a different stack the token is not scoped to).
3. Because `CCMenuController#stack` calls `Stack.from_param!` unscoped, the request succeeds (`200 OK`) and returns Stack B's build status, instead of the `403 Forbidden`/`404` that occurs for other API endpoints (e.g. `Api::StacksController#show`) when a stack-scoped client requests a stack outside its scope.

### Citations

**File:** app/models/shipit/api_client.rb (L7-12)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
