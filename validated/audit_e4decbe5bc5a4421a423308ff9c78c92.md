### Title
Api::CCMenuController bypasses ApiClient stack scoping, allowing cross-stack read of deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces a binding between an `ApiClient`'s `stack_id` scope and which `Stack` a request may touch, by resolving `stack` through the scoped `stacks` relation. `Shipit::Api::CCMenuController` overrides `stack` to bypass this relation and resolve directly from `Stack.from_param!(params[:stack_id])`, breaking the "stack a token authorizes" vs "stack it touches" binding.

### Finding Description
`BaseController#stacks` restricts the queryable stacks to the one the `ApiClient` is scoped to when `current_api_client.stack_id?` is true, otherwise `Stack.all`: [1](#0-0) 

Every other controller inheriting from `BaseController` resolves the target record through `stack`, which uses this scoped `stacks` relation, so an `ApiClient` created with `stack: <stack A>` (as in the `here_come_the_walrus` fixture) can only resolve stacks it is scoped to — a request for another stack's `id`/param raises `ActiveRecord::RecordNotFound` via `from_param!`.

`CCMenuController`, however, defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, entirely skipping the `stacks` scoping helper: [2](#0-1) 

The controller's only access control is `require_permission :read, :stack`, which merely checks that the `ApiClient#permissions` array includes `"read:stack"` — it never checks that the requested `stack_id` matches `current_api_client.stack_id`: [3](#0-2) [4](#0-3) 

This is exactly the class of bug described in the report: a value the deployment authorizes (`current_api_client.stack_id`, the stack the token was created/restricted for) is never checked against the value actually acted upon (`params[:stack_id]`, the stack whose data is returned), because `CCMenuController#stack` re-implements the lookup without the missing "is this the authorized stack" check — analogous to `UncmpPubKeyToCmpPubKey` accepting any `(x, y)` pair without checking it actually lies on the authorized curve.

The controller also supports an alternate authentication path via a bare query-string `token` param (in addition to Basic Auth), which is exactly the mechanism (`CCMenuUrlController`) used to hand out stack-scoped tokens to third parties (e.g., embedding a CCTray/CI status URL): [5](#0-4) [6](#0-5) 

Those tokens are minted with `stack: <specific stack>` and `permissions: ['read:stack']`, precisely to restrict a given holder of that URL/token to reading the status of one stack: [7](#0-6) 

### Impact Explanation
Any holder of a stack-scoped `read:stack` `ApiClient` token — e.g., a CCMenu/CCTray URL that a user shared for one stack's status badge, which is explicitly designed to be embeddable/low-trust — can supply a different `stack_id` in the request and read that other stack's deploy/build status (`lastBuildStatus`, `lastBuildLabel`, lock state, etc.) even though the token was never authorized for that stack. This is an unauthorized cross-stack read of stack state using a credential that the application's own scoping model says should not have access to it, matching the "High: unauthenticated/unauthorized read of stack state" impact category (the attacker only holds a narrowly-scoped credential, not general repository or Shipit access).

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient`s (which is the documented purpose of `CCMenuUrlController`/`ccmenu_url` feature) and hands the resulting URL/token to less-trusted consumers (CI dashboards, status badges, etc.). No special privilege is needed beyond possessing one such legitimately-scoped token; the requester simply changes `stack_id` in the request.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` helper (i.e., `stacks.from_param!(params[:stack_id])`) exactly like `BaseController#stack`, so the `current_api_client.stack_id` restriction is enforced consistently across all API controllers, closing the gap where a stack-scoped token can read arbitrary stacks.

### Proof of Concept
1. As an admin, visit a stack A page and use the CCMenu URL feature (`CCMenuUrlController#fetch`) to mint a `read:stack`-only, stack-A-scoped `ApiClient` token, as shown in `test/controllers/ccmenu_controller_test.rb`: [8](#0-7) 
2. Take the resulting `token` and issue a request to `GET /api/stacks/<STACK_B_ID>/ccmenu.xml?token=<token>` for a *different* stack B that this token is not scoped to.
3. Because `CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of `stacks.from_param!`, the lookup succeeds against stack B and the XML response discloses stack B's `lastBuildStatus`/`lastBuildLabel`/activity, even though the token's `stack_id` (stack A) never matches `params[:stack_id]` (stack B). Compare against `Api::StacksController`, which correctly denies access via the scoped `stacks` relation in an analogous scenario: [9](#0-8)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
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
end
```

**File:** test/controllers/ccmenu_controller_test.rb (L21-25)
```ruby
    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
      end
    end
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
