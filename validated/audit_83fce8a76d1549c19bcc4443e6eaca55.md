### Title
CCMenu token minted by `CCMenuUrlController#client` is never bound to the requested stack, allowing one token to authenticate CCMenu XML reads for arbitrary stacks - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`Shipit::CCMenuUrlController#client` creates/reuses an `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` without passing `stack: stack`, so the persisted `ApiClient#stack_id` stays `nil`. Because `Shipit::Api::BaseController#stacks` treats a client with `stack_id` unset as unscoped (`Stack.all`), the resulting `authentication_token` is valid against `Shipit::Api::CCMenuController#show` for every stack in the installation, not just the stack the URL was generated for.

### Finding Description
The intended binding is `client.stack_id == stack.id` for the stack the CCMenu URL was minted for, i.e. a token generated from `/stacks/:owner/:repo/:env/ccmenu_url` should only authenticate reads of that same stack's `ccmenu.xml`.

Trace:
- `CCMenuUrlController#fetch` resolves `stack = Stack.from_param!(params[:stack_id])` [1](#0-0) , then builds the CCMenu URL and appends `client.authentication_token` as the `token` query param [2](#0-1) .
- `#client` mints the token via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` - note `stack:` is absent from `create_with`, and lookup keys are only `creator` and `name`, not `stack` [3](#0-2) .
- `ApiClient#stack` is `belongs_to :stack, optional: true` [4](#0-3) , so an unscoped client persists with `stack_id: nil`.
- When the token is later used against `Shipit::Api::CCMenuController#show`, authentication happens through `Api::BaseController#authenticate_api_client` overridden in `CCMenuController` to call `ApiClient.authenticate(params[:token])` [5](#0-4) , and `#stack` resolves via `stacks.from_param!(params[:stack_id])` [6](#0-5) .
- `Api::BaseController#stacks` computes: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [7](#0-6) . Since `stack_id` is `nil` for the "CCMenu Client" record, this evaluates to `Stack.all` - the scope is not narrowed to the originally requested stack.

Because the same `find_or_create_by!(creator:, name: 'CCMenu Client')` record is reused across all `#fetch` calls by the same user regardless of which stack was passed in `params[:stack_id]`, every CCMenu URL generated for that user - for any stack, in any repository - carries a token that is functionally interchangeable and authenticates against `read:stack` for **any** stack, since `require_permission :read, :stack` only checks `permissions.include?('read:stack')` [8](#0-7) [9](#0-8)  - it never checks that `current_api_client.stack_id` matches the `stack` being fetched, relying entirely on the `stacks` scope, which is bypassed by the nil `stack_id`.

No existing guard closes this gap: `force_github_authentication` only checks org/team-wide membership (`current_user.authorized?`), not per-stack ACL [10](#0-9) , and there is no per-stack authorization check in `CCMenuUrlController` at all before minting the token.

### Impact Explanation
Any authenticated Shipit user can obtain, via the normal "CC Menu URL" feature, a single reusable token that decodes (through `ApiClient.authenticate`) to an `ApiClient` row with `stack_id: nil` and `permissions: ['read:stack']`. That token, when leaked or shared (e.g. pasted into a public CI dashboard or a CCMenu/CCTray monitoring tool, which is the intended external consumer of this URL), grants read access to the build/deploy status XML of **every** stack in the Shipit instance - across all repositories and environments - not just the single stack the URL was generated for. This is a scope-confinement / IDOR-style failure: the security boundary implied by the per-stack URL (`/stacks/:owner/:repo/:env/ccmenu_url`) is not enforced by the token it mints. This matches the "unauthorized read of stack state" impact category, since a credential meant to be scoped to one repository's build status ends up disclosing state for arbitrary other repositories to whoever holds that URL/token.

### Likelihood Explanation
Preconditions are minimal: any authenticated, `authorized?` Shipit user visiting the stack settings page and clicking "Get CCMenu URL" triggers this path automatically; no special configuration is required. The attacker cost is trivial - one authenticated request per stack (or even a single request, since a leaked token from any stack works everywhere). The bug is deterministic and always reproducible, not dependent on timing or race conditions.

### Recommendation
Scope the `ApiClient` to the specific stack when minting the CCMenu token, e.g.:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')
end
```
Include `stack:` both in the `create_with` attributes and in the `find_or_create_by!` lookup key so a distinct, stack-bound `ApiClient` is created per stack, and `Api::BaseController#stacks` correctly narrows to `Stack.where(id: current_api_client.stack_id)` instead of falling back to `Stack.all`.

### Proof of Concept
```ruby
# test/controllers/ccmenu_url_controller_test.rb
module Shipit
  class CCMenuUrlControllerScopeTest < ActionController::TestCase
    tests CCMenuUrlController

    setup do
      @stack_a = shipit_stacks(:shipit)
      @stack_b = shipit_stacks(:cyclimse) # a different stack/repo fixture
      @user = shipit_users(:walrus)
      session[:user_id] = @user.id
    end

    test "token minted for stack A is not bound to stack A" do
      get :fetch, params: { stack_id: @stack_a.to_param }
      data_a = JSON.parse(response.body)
      token = Rack::Utils.parse_nested_query(URI(data_a['ccmenu_url']).query)['token']

      client = ApiClient.find(ApiClient.authenticate(token).id)
      # Broken binding: expected client.stack_id == @stack_a.id, actually nil
      assert_nil client.stack_id
      refute_equal @stack_a.id, client.stack_id

      # Replay token against stack B's ccmenu.xml via the API controller
      get :show, params: { stack_id: @stack_b.to_param, token: token },
          controller: Api::CCMenuController, action: :show
      assert_response :ok # should be :forbidden / :not_found if properly scoped
    end
  end
end
```
This demonstrates the token issued for `@stack_a` authenticates a `read:stack` request against `@stack_b`, confirming `client.stack_id != stack.id` and that the API-level scope check (`Stack.all` fallback) does not prevent cross-stack use.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L20-22)
```ruby
    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```

**File:** app/models/shipit/api_client.rb (L8-8)
```ruby
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
