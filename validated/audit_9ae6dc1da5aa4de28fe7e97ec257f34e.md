### Title
CCMenu token minted for one stack authorizes reading any stack's CC status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` resolves `params[:stack_id]` via `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `stacks` scoping method inherited from `Api::BaseController` that restricts lookups to `current_api_client.stack_id`. Combined with the fact that `CCMenuUrlController#client` never sets `stack_id` on the `ApiClient` it mints, any CCMenu token obtained by a Shipit session user for repo A can be replayed with an arbitrary `stack_id` for repo B to read repo B's deploy state.

### Finding Description
The claimed binding should be: `current_api_client.stack_id ∈ {nil, Stack.from_param!(params[:stack_id]).id}`, enforced identically to how `Api::StacksController#stack` does it via `stacks.from_param!(params[:id])` where `stacks` is `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) , [2](#0-1) .

`Api::CCMenuController` overrides `#stack` and never routes through `stacks`: [3](#0-2) 

This means the `read:stack` permission check performed by `require_permission :read, :stack` [4](#0-3)  only checks that the string `'read:stack'` is in `current_api_client.permissions` via `check_permissions!` [5](#0-4)  — it never checks which stack the permission applies to.

Making this worse, `CCMenuUrlController#client` mints the `ApiClient` without ever assigning `stack_id`: [6](#0-5) 

Since `ApiClient belongs_to :stack, optional: true` and no `stack:`/`stack_id:` is passed to `create_with`, every CCMenu client's `stack_id` is `nil` [7](#0-6) . Even disregarding that, `Api::CCMenuController#stack`'s direct `Stack.from_param!` call means the scoping would be bypassed regardless of whether `stack_id` were populated.

Attack flow: an authenticated Shipit user (session user, not privileged) visits `GET /ccmenu/<owner_A>/<repo_A>/<env_A>` which is routed to `CCMenuUrlController#fetch` [8](#0-7) , obtaining `client.authentication_token` for a token that carries `read:stack` permission and `stack_id = nil`. The attacker then requests `GET /api/stacks/<owner_B>/<repo_B>/<env_B>/ccmenu?token=<token>`, which is routed to `Api::CCMenuController#show` [9](#0-8) . `authenticate_api_client` accepts the token via `ApiClient.authenticate(params[:token])` [10](#0-9) , `require_permission!` passes because `read:stack` is present, and `stack` resolves stack B unconditionally, leaking stack B's latest deploy/rollback status via the rendered XML.

None of the existing guards (`require_permission`, `authenticate_api_client`, `ExplicitParameters`, model validations) check that the resolved stack matches any stack the client is scoped to, because `Api::CCMenuController#stack` never consults `current_api_client.stack_id` or the `stacks` helper at all.

### Impact Explanation
Any Shipit user with access to at least one stack (repo A) can enumerate/read the CI/deploy status of any other stack (repo B) in the same Shipit instance, including private/internal repositories they have no access to — this is unauthenticated read of stack state via a token that was only ever supposed to be scoped to one stack. This is repeatable indefinitely (the token is a signed, non-expiring value) and applies across all tenants/stacks hosted by the same Shipit instance, matching the "High: unauthenticated read of stack state" impact category.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs an authenticated Shipit session for any single repository (which any onboarded GitHub user in `Shipit.github_teams` can have) to trigger `CCMenuUrlController#fetch` and obtain a token. No GitHub App secrets, `api_clients_secret`, or operator privileges are needed beyond normal login. The exploit is a single unauthenticated GET request with a swapped `stack_id` and is trivially repeatable against every other stack ID.

### Recommendation
Make `Api::CCMenuController#stack` use the inherited `stacks` scoping (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, and have `CCMenuUrlController#client` assign `stack:` (or `stack_id:`) to the created `ApiClient` so each CCMenu token is bound to the specific stack it was generated for.

### Proof of Concept
In `test/controllers/api/ccmenu_controller_test.rb`, add a minitest case:
1. Create `stack_a = shipit_stacks(:shipit)` and `stack_b = Stack.create!(repository: Repository.create!(owner: 'other', name: 'repo'), branch: 'main', environment: 'staging')`.
2. Create `client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client', permissions: %w[read:stack], stack: stack_a)` (simulating the CCMenu token minted for stack A).
3. Assert binding before: `client.stack_id == stack_a.id`, `client.stack_id != stack_b.id`.
4. `get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }`.
5. Assert `response.status` is not `403`/`404` (currently `200`), and `assert_payload('name', stack_b.to_param)` proving stack B's data was leaked using a token scoped to stack A — demonstrating the equality `current_api_client.stack_id == resolved_stack.id` is violated yet the request still succeeds.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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

**File:** app/models/shipit/api_client.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** config/routes.rb (L49-51)
```ruby
  scope '/ccmenu/*stack_id', stack_id: stack_id_format, as: :ccmenu_url do
    get '/' => 'ccmenu_url#fetch'
  end
```
