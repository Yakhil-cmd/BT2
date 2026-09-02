### Title
CCMenuController bypasses both `Shipit.github_teams` and per-stack API token scoping, exposing any stack's deploy history to a token issued for a different stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The web UI enforces `force_github_authentication` plus `User#authorized?` (GitHub team membership) before showing a stack's deploy status, but `Shipit::Api::CCMenuController#show` only requires a valid `ApiClient` token with the generic `read:stack` permission and never checks team membership or that the token is scoped to the requested stack. Because `CCMenuUrlController` also creates a token that is not bound to a specific stack, any CCMenu token a user has ever obtained can be replayed against `cc_menu.xml` for any other stack id/slug in the system.

### Finding Description
The binding that should hold is: `authorization_to_view_stack_via_web_UI(stack) == authorization_to_view_stack_via_cc_menu_xml(stack)`, where the web-UI side is `current_user.authorized?` (membership in `Shipit.github_teams`, enforced in `force_github_authentication` at [1](#0-0)  and [2](#0-1) ).

On the API side, `CCMenuController` overrides authentication to use only the token param and overrides `stack` lookup to bypass the `stacks` scoping used everywhere else in the API: [3](#0-2) 

Compare this to `BaseController#stack`, which restricts lookups to `current_api_client.stack_id` when the client is scoped to one: [4](#0-3) 

`CCMenuController#stack` does not call `stacks`; it calls `Stack.from_param!(params[:stack_id])` directly against all stacks, so even a stack-scoped token (if one existed) would not be constrained. `require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks a global permission string, not stack identity: [5](#0-4) 

Compounding this, the token minted by `CCMenuUrlController#client` is created without any `stack:` association at all, and is memoized by `creator + name` only ("CCMenu Client"), so the exact same token is reused/returned for every stack a given user requests a CCMenu URL for: [6](#0-5) 

Neither `force_github_authentication` nor `User#authorized?` (team check) is ever invoked on the `Shipit::Api::CCMenuController` request path, since it inherits from `BaseController < ActionController::Base` (API namespace), not from `ShipitController`/`Authentication` concern. The attacker's request is: obtain (via any lawful means, e.g. their own CCMenu URL for a stack they can access) a `token`, then `GET /api/stacks/<private_stack_B_id_or_slug>/cc_menu.xml?token=<token>`. The controller authenticates the token, checks the generic `read:stack` permission (satisfied), loads stack B unconditionally, and renders `stack.deploys_and_rollbacks.last`, exposing deploy/task status for a stack the attacker has no team membership for and for which the token was never intended.

### Impact Explanation
The endpoint discloses the latest deploy/rollback id, status (`running?`), and completion time for an arbitrary stack to a caller who is not a member of `Shipit.github_teams` and thus could not view the same information via the web UI or the deploys/tasks stream. This is a cross-tenant/cross-stack unauthenticated (relative to intended authorization) read of deploy state, matching the "unauthenticated read of stack state, task streams or deploy output" High-severity category. It is fully repeatable: the same token, or a token minted for any stack, can be replayed against every stack id/slug the attacker enumerates, since neither the stack scoping nor the team check is applied.

### Likelihood Explanation
The attacker needs any valid CCMenu API token — one they can legitimately obtain for a stack they can view — and only needs to guess or enumerate another stack's numeric id or slug (`Stack.from_param!`), which is low-cost and requires no GitHub or Shipit secret. No special Shipit configuration is required; the divergence exists by default because `CCMenuController` was written to bypass the standard `stacks` scoping present in `BaseController`.

### Recommendation
- In `CCMenuController#stack`, scope the lookup through `stacks` (or explicitly check `current_api_client.stack_id.nil? || current_api_client.stack_id == requested_stack.id`) so a token cannot be replayed against stacks other than the one it was issued for.
- Bind the token created in `CCMenuUrlController#client` to the specific stack (`stack:` attribute) instead of a global per-user "CCMenu Client", and include the stack in the `find_or_create_by!` lookup key.
- Optionally, enforce `Shipit.github_teams` membership of the token's `creator` at request time so revoked/removed team members lose CCMenu access consistent with the web UI.

### Proof of Concept
Minitest plan (`test/controllers/api/ccmenu_controller_test.rb`):
```ruby
test "#show exposes deploy data for an unrelated stack using a token scoped to a different stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # a different, "private" stack

  # token minted the normal way, for stack_a, by a user who is a team member of stack_a's team only
  creator = shipit_users(:walrus)
  Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)]) # creator is NOT a member
  client = ApiClient.create!(creator: creator, name: 'CCMenu Client', permissions: %w[read:stack])
  token = client.authentication_token

  # Assert web UI would deny (binding LHS)
  session_user = creator
  assert_equal false, session_user.authorized?

  # Assert API path still returns 200 with deploy data for stack_b (binding RHS should equal LHS but doesn't)
  get :show, params: { stack_id: stack_b.to_param, token: token }
  assert_response :ok
  assert_match(/Project name=/, response.body) # confirms deploy data for stack_b leaked despite no team membership and token not scoped to stack_b
end
```
This demonstrates the divergence: `session_user.authorized?` is `false` (web UI would reject with 403 per `force_github_authentication`), yet the CCMenu API `show` action returns `200` with stack B's deploy data using a token that was neither issued for stack B nor backed by any team-membership check.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
