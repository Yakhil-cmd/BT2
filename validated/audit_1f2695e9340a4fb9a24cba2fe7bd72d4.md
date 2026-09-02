### Title
CCMenu token minted for one stack grants read access to every stack in the instance - (File: `app/controllers/shipit/ccmenu_url_controller.rb`, `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`CCMenuUrlController#client` creates the `ApiClient` used for the per-stack CCMenu feed without ever assigning `stack:`, leaving `client.stack_id` `nil`. `CCMenuController#show` additionally defines its own `stack` method that looks up `Stack.from_param!(params[:stack_id])` directly, bypassing the scoped `stacks` helper from `Api::BaseController` that would otherwise restrict a client to its own stack. The combination means a CCMenu token generated for stack A's URL authenticates read access to the CCMenu XML of any stack B in the instance.

### Finding Description
The intended binding is `client.stack_id == stack.id` for every `ApiClient` minted by `CCMenuUrlController#fetch`, so that `Api::BaseController#stacks` (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) restricts the token to that one stack. [1](#0-0) 

`client` is created with `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — `stack:` is never passed, so `client.stack_id` is `nil` for every user regardless of which stack's CCMenu URL was fetched. `find_or_create_by!` also means the *same* `ApiClient` record (keyed only on `creator` + `name`) is reused across every stack a given user fetches a CCMenu URL for, so one token literally works for stack A, B, C, etc.

Independently, `CCMenuController` never consults the scoped `stack_id` at all: [2](#0-1) 

Compare with the scoping mechanism it should be using, defined in the base class: [3](#0-2) 

`CCMenuController#stack` overrides this with `Stack.from_param!(params[:stack_id])`, so even if `client.stack_id` were correctly populated, the per-stack restriction would still never be enforced for this endpoint. `require_permission :read, :stack` only calls `check_permissions!`, which validates the permission string `read:stack` is present — it never checks scope/`stack_id`.

Attack: an authenticated Shipit user (any user, since this only requires a logged-in session, and the finding here concerns cross-stack disclosure once *any* token is obtained/observed) fetches `GET /ccmenu/*stack_id` for stack A, obtaining a token via `ccmenu_url#fetch`. That same token, sent as `?token=` to `GET /api/stacks/*stack_id/ccmenu` for an unrelated stack B, succeeds and returns B's latest deploy/build status because `client.stack_id` is `nil` and `CCMenuController#stack` doesn't check it anyway.

### Impact Explanation
A CCMenu token believed to be scoped to a single stack's build-status feed instead discloses the CCMenu status (latest deploy/rollback outcome, timestamps) of every stack in the Shipit instance to the holder of that token. This is a scope-authorization break: `read:stack` permission checking exists but the per-resource scope constraint that is supposed to accompany a CCMenu token is not enforced anywhere on the read path. This matches "escalation into ... unauthenticated read of stack state" for any stack other than the one the token was minted for; the leak is repeatable indefinitely and applies across every stack/tenant in the instance since the query is a simple `GET` with the stale token.

### Likelihood Explanation
No special privilege beyond having ever obtained a legitimate CCMenu URL/token for one stack is required; the attacker cost is a single authenticated fetch of their own stack's CCMenu URL (if they have read access to at least one stack) plus reusing that token against arbitrary `stack_id` values in `GET /api/stacks/*stack_id/ccmenu`. No secrets, webhook signing, or GitHub credentials are needed. This is fully reproducible without live GitHub, purely via Shipit's own routes and models.

### Recommendation
Set `stack: stack` when creating the `ApiClient` in `CCMenuUrlController#client` (and stop keying `find_or_create_by!` solely on `creator`/`name` so distinct stacks get distinct scoped clients), and change `CCMenuController#stack` to use the inherited scoped `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`, so the token's `stack_id` is actually enforced.

### Proof of Concept
```ruby
# test/controllers/ccmenu_controller_test.rb (new test)
test "ccmenu token scoped to one stack cannot read another stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # any other fixture stack
  session[:user_id] = shipit_users(:walrus).id

  get :fetch, params: { stack_id: stack_a.to_param } # ccmenu_url#fetch
  data = JSON.parse(response.body)
  token = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)['token']

  client = ApiClient.last
  assert_nil client.stack_id # binding client.stack_id == stack_a.id is violated

  get :show, params: { stack_id: stack_b.to_param, token: token } # api/ccmenu#show
  assert_response :ok # should be :not_found/:forbidden, proving cross-stack read
end
```

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```
