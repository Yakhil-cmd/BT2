### Title
`CCMenuUrlController#fetch` mints a global-scope API token because `ApiClient.create_with(...).find_or_create_by!` omits `stack:` - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

### Summary
`CCMenuUrlController#fetch` creates (or reuses) an `ApiClient` keyed only by `creator` and `name`, never setting `stack:`, so the resulting token's `stack_id` is `nil`. Because `Api::BaseController#stacks` treats a nil `stack_id` as "unscoped," the token minted while viewing one stack's CCMenu URL authenticates for *every* stack the API exposes.

### Finding Description
The broken binding is: the token returned to the user for stack A must satisfy `current_api_client.stack_id == stack_A.id`, but in practice `current_api_client.stack_id == nil`.

Code path:
- `Shipit::CCMenuUrlController#fetch` builds `client.authentication_token` and embeds it in `ccmenu_url` as `token=...`: [1](#0-0) 
- `client` is created with `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, with no `stack:` attribute at all: [2](#0-1) 
- `ApiClient#stack` is `optional: true`, so the record persists with `stack_id: nil`: [3](#0-2) 
- `authentication_token` just signs the client's `id`, carrying no stack binding: [4](#0-3) 
- Any API controller inheriting `Api::BaseController` (e.g. `Api::StacksController`, `Api::TasksController`) resolves accessible stacks via `stacks`, which only restricts to a single stack `if current_api_client.stack_id?`; when `stack_id` is nil it falls back to `Stack.all`: [5](#0-4) 

Attacker flow: an authenticated low-trust user with a session (`session[:user_id]`) who can see stack A visits `GET /ccmenu/<stack_A_id>`. `fetch` creates/finds an `ApiClient` for that user with `read:stack` permission and no stack restriction, then returns a URL like `.../ccmenu/stacks/<stack_A_id>?token=<signed id>`. The attacker extracts `token` and calls `GET /api/stacks` or `GET /api/stacks/<stack_B_id>/tasks` with HTTP Basic auth using that token. `authenticate_api_client` accepts it via `ApiClient.authenticate(token)`, and since `stack_id` is nil, `stacks` returns `Stack.all`, exposing stack B's data despite `require_permission :read, :stack` only checking the `read:stack` string, not stack identity: [6](#0-5) 

No existing guard catches this: `require_permission!` only validates the permission name, not stack scope; `Stack.from_param!` in the CCMenu URL controller itself is unrelated to the API client's own scoping; and there is no validation forcing `ApiClient#stack` to be present for stack-scoped clients. This is also reinforced by `find_or_create_by!` matching solely on `creator`+`name`, so once created, the *same* unscoped client/token is reused and returned for any subsequent stack the user visits via `/ccmenu/*`, compounding the exposure across all stacks the user has ever fetched a CCMenu URL for.

### Impact Explanation
An authenticated user with visibility into just one stack can obtain a long-lived Basic-Auth-style API token that reads (via `read:stack`) any stack, its tasks, and other stack-scoped resources served by `Api::BaseController` subclasses that don't further restrict `stack`. This is a cross-tenant unauthorized read of stack state and task/deploy data, matching the High severity category "unauthorized read of stack state, task streams or deploy output" — potentially Critical-adjacent since it can be leveraged repeatably against arbitrary stacks with a single lightweight, unprivileged action (visiting a URL for one's own visible stack).

### Likelihood Explanation
Preconditions are minimal: the attacker only needs an existing Shipit session and visibility to at least one stack (a very low bar in typical Shipit deployments where many stacks are visible to all logged-in users). No secrets, GitHub tokens, or elevated roles are required. The action (`GET /ccmenu/:stack_id`) is a normal, expected UI flow, making this trivially discoverable and repeatable.

### Recommendation
Bind the `ApiClient` to the specific stack when creating/finding it, e.g. `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`, and include `stack:` in both the `find_or_create_by!` lookup and creation attributes so distinct clients/tokens are minted per stack, ensuring `current_api_client.stack_id?` is true and correctly scopes to the intended stack only.

### Proof of Concept
Minitest plan (extending `test/controllers/ccmenu_controller_test.rb` and an API test):
```ruby
test ":fetch token is scoped to the requested stack only" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Shipit::Stack.create!(repository: shipit_repositories(:shipit), environment: 'other')

  get :fetch, params: { stack_id: stack_a.to_param }
  data = JSON.parse(response.body)
  token = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)['token']
  client = Shipit::ApiClient.last

  # Broken binding check
  assert_nil client.stack_id # currently nil instead of stack_a.id -> vulnerability present

  # Exploit: use token to read stack_b via API
  @request.env['HTTP_AUTHORIZATION'] =
    ActionController::HttpAuthentication::Basic.encode_credentials(token, '')
  get "/api/stacks/#{stack_b.to_param}/tasks", headers: { 'Authorization' => @request.env['HTTP_AUTHORIZATION'] }
  assert_response :ok # should be :not_found/:forbidden if properly scoped
end
```
Assertions: `client.stack_id` (actual: `nil`) vs expected `stack_a.id` — mismatch proves the broken binding; the subsequent `/api/stacks/:stack_b_id/tasks` request returning `200 OK` with stack B data (instead of being denied) proves the cross-stack read impact.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L8-8)
```ruby
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```
