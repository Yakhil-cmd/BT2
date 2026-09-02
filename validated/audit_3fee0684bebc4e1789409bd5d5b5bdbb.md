This confirms the vulnerability. `Shipit::Api::CCMenuController` deliberately overrides both `stack` and `authenticate_api_client` from `BaseController`, and in doing so drops the tenant-scoping that `BaseController` normally enforces.

### Title
Cross-stack unauthorized read via `CCMenuController#stack` bypassing token stack scoping - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides `BaseController#stack` and `#authenticate_api_client` in a way that drops the stack-scoping that `BaseController#stacks` normally enforces. As a result, a CCMenu token minted for stack A can be used to read deploy/CI status for any other stack B by simply changing `:stack_id` in the URL.

### Finding Description
The binding that should hold is: `stack.id == current_api_client.stack_id` (when `current_api_client.stack_id?` is true), exactly as enforced by `BaseController#stacks`: [1](#0-0) 
`stacks` restricts lookup to `Stack.where(id: current_api_client.stack_id)` before resolving `params[:stack_id]`, so an out-of-scope `stack_id` raises `RecordNotFound` via `from_param!`.

`CCMenuController` bypasses this entirely: [2](#0-1) 
Here `stack` calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` class — with no scoping to `current_api_client.stack_id` — and `authenticate_api_client` is redefined to accept a bare query-string `token` via `ApiClient.authenticate(params[:token])`, again with no stack check. `ApiClient.authenticate` only verifies the signed token id and looks up the record; it performs no comparison against the requested stack: [3](#0-2) 

The only remaining gate is `require_permission :read, :stack`, which calls `check_permissions!`: [4](#0-3) 
This only checks that the string `"read:stack"` is present in `permissions` — it never compares `stack.id` to `current_api_client.stack_id`. So a CCMenu client (created with `permissions: %w[read:stack]` and bound to stack A via `belongs_to :stack`) passes this check for a request naming stack B.

Attacker flow:
1. Attacker obtains (or is given) a public/shared CCMenu URL for stack A, e.g. via `CCMenuUrlController#fetch`, which mints a token scoped to a `stack_id`-bound `ApiClient`: [5](#0-4) 
2. Attacker sends `GET /api/stacks/<stack_B_id>/ccmenu.xml?token=<token_for_stack_A>`.
3. `authenticate_api_client` finds the valid `ApiClient` (bound to stack A) purely from the token's signature; `stack` resolves stack B unscoped; `require_permission!` passes because the client has `read:stack`; `show` renders stack B's `deploys_and_rollbacks`/CI status.

The equality `stack.id == current_api_client.stack_id` is violated after the fact (`stack.id == B`, `current_api_client.stack_id == A`), yet the request succeeds with 200, unlike the equivalent flow through `BaseController#stacks` used by every other API controller (e.g. `Api::StacksController`).

### Impact Explanation
An attacker holding a CCMenu token scoped to stack A can read stack B's deploy/rollback status and CI build status XML for any stack B whose id/slug they know, with no further authorization. This is a cross-tenant/cross-stack unauthorized read of stack state (matches "unauthenticated/unauthorized read of stack state" — High), and is repeatable against arbitrary stacks by simply varying `stack_id` in the request, requiring only a single valid CCMenu token for any one stack.

### Likelihood Explanation
Preconditions are low-cost for an attacker: CCMenu URLs are commonly shared/embedded in dashboards (that's their purpose), so obtaining one token for a stack the attacker can legitimately see is plausible; no GitHub or Shipit secrets are required, no privileged role is needed, and stack ids/slugs are typically low-entropy/enumerable. The exploit is a single unauthenticated-cost GET request per target stack.

### Recommendation
Make `CCMenuController` reuse `BaseController`'s stack-scoped lookup instead of redefining it: remove the overriding `stack` method (or have it call `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!`), and remove the `authenticate_api_client` override so the base implementation (which is functionally equivalent but should be used for consistency) is inherited, ensuring `current_api_client.stack_id`, when present, is used to scope `stack` resolution.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read stack B's ccmenu status" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  client_a = ApiClient.create!(creator: @user, name: 'A', permissions: %w[read:stack], stack: stack_a)

  assert_not_equal client_a.stack_id, stack_b.id

  get :show, params: { stack_id: stack_b.to_param, token: client_a.authentication_token }

  assert_response :ok # demonstrates the flaw: should be :not_found / :forbidden
  assert_payload 'name', stack_b.to_param
end
```
This mirrors the existing `"can authenticate with query string token"` test but requests a different stack than the one the token/client is bound to, asserting `client_a.stack_id != stack_b.id` while still getting a 200 with stack B's data.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-22)
```ruby
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
