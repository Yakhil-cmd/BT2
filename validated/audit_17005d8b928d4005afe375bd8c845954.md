This confirms the vulnerability. The `stacks` method scoping is exactly as described, and `CCMenuUrlController#client` genuinely creates a stack-unscoped `ApiClient`.### Title
CCMenu API client is created stack-unscoped, letting `Shipit::Api::BaseController#stacks` widen its authorization to every stack on the instance - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Shipit::Api::BaseController#stacks` scopes an API request to the caller's own stack only `if current_api_client.stack_id?`, otherwise it returns `Stack.all`. `Shipit::CCMenuUrlController#client` creates the `ApiClient` used for the per-stack CCMenu integration without ever setting `stack:`, so its `stack_id` is `nil` and `stack_id?` is false, meaning a token minted for one stack's CCMenu URL can list and read every stack on the Shipit instance via the API.

### Finding Description
The intended binding is: **stack set an API request authorizes = {stacks belonging to `current_api_client.stack_id`}**. The actual binding realized by the code is: **stack set authorized = `current_api_client.stack_id? ? {stack_id} : Stack.all`**, per [1](#0-0) . These diverge whenever `stack_id` is `nil`.

`Shipit::CCMenuUrlController#client` is the code path that produces such an `ApiClient`:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
``` [2](#0-1) 

No `stack:` attribute is passed to `create_with`/`find_or_create_by!`, and `ApiClient#stack` is `optional: true` per [3](#0-2) , so the created/found record has `stack_id: nil`. Because the lookup key is only `creator + name` (`'CCMenu Client'`), a single user requesting CCMenu URLs for any stack they can view gets one shared, unscoped `ApiClient` with `read:stack` permission and an `authentication_token` (`ApiClient#authentication_token`, [4](#0-3) ) that they can extract from the returned `ccmenu_url` query string, per [5](#0-4) .

Exploit flow: an authenticated Shipit user (any user who can reach `CCMenuUrlController#fetch` for at least one stack they're permitted to view) fetches `GET /stacks/:owner/:repo/:env/ccmenu_url`, obtains `client.authentication_token` from the response, then issues `GET /api/stacks` with `Authorization: Basic <token>--` (per the `BasicAuth.authenticate` join logic in `authenticate_api_client`, [6](#0-5) ). `Api::StacksController#index` calls `stacks` (`require_permission :read, :stack`), which — because `stack_id` is nil — returns `Stack.all` instead of the single stack, exposing every stack's id/repo/branch/environment metadata across all tenants, per [7](#0-6) .

Existing guards do not stop this: `require_permission!` only checks the `read:stack` string is present in `permissions` (`ApiClient#check_permissions!`, [8](#0-7) ) and never checks `stack_id`; `authenticate_api_client` only validates the HMAC signature of the token via `SimpleMessageVerifier`, not its scope.

### Impact Explanation
Any user who has view access to at least one stack's CCMenu URL can obtain a `read:stack`-scoped API token that is unscoped (`stack_id: nil`) and use it to enumerate and read `Stack.all` via `GET /api/stacks`, and additionally `show` (`Api::StacksController#show`) any other tenant's individual stack by id, since `stacks.from_param!` also resolves against `Stack.all` for this client. This is an unauthorized read of stack state across every repository/tenant on the instance — matching the "High: unauthenticated/unauthorized read of stack state" category. It is fully repeatable: the token is durable (a persistent DB-backed `ApiClient` row), reusable indefinitely, and works against arbitrary stacks with no additional preconditions per request.

### Likelihood Explanation
Preconditions are modest: the attacker only needs to be a legitimate Shipit user with access to any single stack's CCMenu integration page (a very low-privilege, commonly available Shipit UI feature), and the target instance must host multiple stacks/tenants (typical for a shared Shipit deployment). No secrets (`api_clients_secret`, `secret_key_base`, GitHub tokens) need to be known or stolen — the CCMenu endpoint hands the attacker a valid signed token directly. Cost is a single authenticated HTTP request plus one more request to the JSON API; fully feasible and repeatable.

### Recommendation
Set `stack:` (the stack being requested) when creating/finding the CCMenu `ApiClient` in `CCMenuUrlController#client`, and include the stack in the `find_or_create_by!` lookup key so each stack gets its own scoped client (e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)`), so `stack_id?` is true and `stacks` correctly narrows to that single stack. Additionally, consider having `Api::BaseController#stacks` treat a `nil` `stack_id` for non-`UnlimitedApiClient` instances as "no access" rather than "all access", to fail closed.

### Proof of Concept
Minitest plan (`test/controllers/api/stacks_controller_test.rb`):
1. Create `user = create(:user)`.
2. Create two stacks belonging to different repositories: `stack_a = create(:stack)`, `stack_b = create(:stack)`.
3. Simulate the CCMenu flow's bug directly: `client = ApiClient.create!(creator: user, name: 'CCMenu Client', permissions: %w[read:stack])` (no `stack:` set, reproducing `CCMenuUrlController#client`'s actual behavior).
4. Assert precondition: `assert_not client.stack_id?`.
5. `get api_stacks_url, headers: { 'Authorization' => ActionController::HttpAuthentication::Basic.encode_credentials(client.authentication_token, '') }`.
6. Parse JSON body and assert it contains both `stack_a.id` and `stack_b.id` — i.e. `assert_includes returned_ids, stack_a.id` and `assert_includes returned_ids, stack_b.id`, proving the token minted for/around a single stack context enumerates unrelated stacks, breaking the intended `stacks == {stack_id}` binding.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
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
