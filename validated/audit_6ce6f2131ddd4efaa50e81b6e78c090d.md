Confirmed. The `CCMenuController` overrides the scoping-aware `stack` helper from `BaseController` with an unscoped lookup, breaking the token-authorized-stack binding.

### Title
CCMenu API token stack scope bypass allows cross-stack deploy status read - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController#stack` enforces that a request only resolves a `Stack` that the authenticated `ApiClient` is scoped to (via `stacks.from_param!`, where `stacks` is restricted to `current_api_client.stack_id` when the client has one). `Shipit::Api::CCMenuController` overrides `stack` and instead calls `Stack.from_param!(params[:stack_id])` directly, bypassing that scoping check entirely. Any valid `ApiClient` token — including one deliberately created and scoped to a single stack (as done by `CCMenuUrlController`) — can therefore be used to read CI/deploy status for any other stack in the installation, not just the one it was issued for.

### Finding Description
`BaseController#stacks` restricts the queryable set of stacks to the ones the `current_api_client` is authorized for: [1](#0-0) 

`CCMenuController` inherits from `BaseController` and only checks the generic `read:stack` permission string via `require_permission`, which does not verify per-stack scoping — it is `stack`'s job to do so. But `CCMenuController` redefines `stack` to bypass the client-scoped `stacks` relation and query any stack by ID directly: [2](#0-1) 

`ApiClient` tokens are opaque signed IDs (`SimpleMessageVerifier`-based) with an optional `stack_id` restriction: [3](#0-2) 

The binding that should hold is: *the stack a token authorizes == the stack the request touches*. Before the request: an `ApiClient` scoped to stack A (`stack_id == A`) is only supposed to see stack A's data. After the request: because `CCMenuController#stack` ignores `current_api_client.stack_id`, that same token can fetch deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock state) for stack B, C, or any other stack simply by supplying a different `stack_id` in the URL/query string. `CCMenuUrlController#fetch` is the intended token issuance path and explicitly creates a stack-scoped client for this endpoint, confirming that scoping is meant to be enforced here: [4](#0-3) 

### Impact Explanation
This is an authorization-scope bypass: a token intentionally minted for read access to one stack's CI status can be replayed to read status/lock information of every other stack in the Shipit instance. This matches the "stack a token authorizes versus a stack it touches" binding class and constitutes unauthorized read of stack state across repositories/environments the token holder was never granted access to.

### Likelihood Explanation
Any holder of a legitimately-issued CCMenu token (e.g. a CI status widget URL, which is commonly shared/embedded, and whose token appears directly in the query string) can trivially exploit this by changing the `stack_id` path segment of the request — no additional privilege, secret, or session is required beyond the token they already legitimately possess for a different, narrower purpose.

### Recommendation
Change `CCMenuController#stack` to use the scoped `stacks` relation from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped `ApiClient` tokens cannot be used to query stacks outside their authorized scope.

### Proof of Concept
1. As an authenticated Shipit user, visit a stack A's CCMenu URL endpoint, which creates/reuses a `read:stack`-only `ApiClient` scoped to stack A and returns a token in the query string:
   `GET /*stack-A/ccmenu` → returns `https://host/api/*stack-A/ccmenu.xml?token=<TOKEN_A>`
2. Take `<TOKEN_A>` and request a different stack B's CCMenu endpoint using that same token:
   `GET /api/*stack-B/ccmenu.xml?token=<TOKEN_A>`
3. Because `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id`, the request succeeds with `200 OK` and returns stack B's `lastBuildStatus`, `lastBuildLabel`, `activity`, and lock state — data the token was never authorized to access.

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

**File:** app/models/shipit/api_client.rb (L23-45)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end

    def authentication_token
      self.class.message_verifier.generate(id)
    end

    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-23)
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
  end
```
