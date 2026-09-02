### Title
CCMenu token grants `read:stack` forever, even after creator's GitHub team membership is revoked - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Api::BaseController#authenticate_api_client` and `ApiClient#check_permissions!` only validate the static `permissions` array stored on the `ApiClient` record at mint time; neither re-checks the creator's current GitHub team membership (`User#authorized?`) on each API request. Once `CCMenuUrlController#fetch` mints a `read:stack` token for a user, that token keeps working against `Api::CCMenuController#show` indefinitely, even after the creator is removed from `Shipit.github_teams`.

### Finding Description
The claimed binding — `current_api_client`'s effective `stacks` scope == creator's CURRENT GitHub authorization, re-validated per request — does not hold in this codebase.

- `CCMenuUrlController#fetch` mints (or reuses) an `ApiClient` scoped to `read:stack` for `current_user` at token-mint time: [1](#0-0) 
- The interactive/session flow enforces authorization on every HTML request via `Shipit::Authentication#force_github_authentication`, which calls `current_user.authorized?` (team membership check) before rendering: [2](#0-1) 
- `Api::BaseController`, which `Api::CCMenuController` extends, does **not** include `Shipit::Authentication` at all. It only runs `authenticate_api_client`, which authenticates the *token* (`ApiClient.authenticate`) and then `require_permission!` → `current_api_client.check_permissions!`: [3](#0-2) 
- `ApiClient#check_permissions!` only checks the static `permissions` array persisted on the row; it never dereferences `creator` or calls `creator.authorized?`: [4](#0-3) 
- `Api::CCMenuController` overrides `authenticate_api_client` purely to accept the token from `params[:token]` instead of Basic Auth, but does not add any creator re-validation: [5](#0-4) 

So replaying `client.authentication_token` against `Api::CCMenuController#show` succeeds purely based on `ApiClient#permissions`, regardless of whether `client.creator.authorized?` later becomes `false` (e.g., their team membership record is deleted).

**However**, this codebase's authorization model (`User#authorized?`) is a single global gate — membership in *any* configured `Shipit.github_teams` — not a per-repository grant: [6](#0-5) . There is no per-repository ACL in this engine beyond that global team check; `repositories_contributed_to`/`stacks_contributed_to` are just UI convenience scopes, not authorization gates. So the premise "authorized on the target repository" collapses to "member of the configured Shipit team(s)," and the finding is that this global gate is never re-checked for token-authenticated API/CCMenu requests — which is exactly what the question describes, just without the (non-existent) per-repository granularity.

This is a genuine, reproducible divergence: `ApiClient.permissions` (static, set at creation) is checked, while `creator.authorized?` (dynamic, current team membership) is never checked on the API/CCMenu path.

### Impact Explanation
Effect: a previously-issued CCMenu API token continues to grant `read:stack` (build status/activity via CCMenu XML) for its scoped stack after the creator is deprovisioned from the required GitHub team(s). This is unauthenticated-in-practice continued read access to stack state (build status, last deploy) once the token has leaked or been retained, matching the High-severity category "unauthenticated read of stack state... after revocation." It is repeatable indefinitely (the token never expires and is re-derivable via `ApiClient#authentication_token`/`ApiClient.authenticate`), but is scoped only to the single stack for which the token was minted — it does not escalate into other stacks, does not grant write/deploy, and does not cross tenants beyond the one stack tied to that `ApiClient`.

### Likelihood Explanation
Requires that a CCMenu token was minted for the now-revoked user (via `CCMenuUrlController#fetch`, an authenticated, in-scope action available to any authorized user before revocation) and that the token was retained/leaked. No secrets are needed to demonstrate the bug because it is an authorization-model gap, not a signature bypass. This is fully feasible/reproducible against this engine's own code and Shipit configuration without any live GitHub access.

### Recommendation
Re-validate `current_api_client.creator.authorized?` (and any per-repository criteria, if introduced later) on every `Api::BaseController` request — not only `ApiClient.permissions` — or revoke/expire `ApiClient` tokens automatically when their `creator` loses required team membership (e.g., a background job that destroys/deactivates `ApiClient`s whose `creator` is no longer `authorized?`).

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (new test)
test "stale CCMenu token still grants read:stack after creator's team membership is revoked" do
  user = shipit_users(:walrus)
  stack = shipit_stacks(:shipit)

  # Mint a CCMenu token for `user` while authorized (simulates CCMenuUrlController#fetch flow)
  client = ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: user, name: 'CCMenu Client')
  token = client.authentication_token

  # BEFORE: creator is authorized, current_api_client.permissions == read:stack
  assert user.authorized?

  # Revoke creator's authorization (simulate GitHub team membership removal)
  user.teams.clear
  Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)]) # not a member of any configured team

  # AFTER: binding breaks -- creator.authorized? is now false, but token access is unaffected
  refute user.reload.authorized?

  get :show, params: { stack_id: stack.to_param, token: token }
  assert_response :ok # BUG: should be :forbidden/:unauthorized once creator loses authorization
end
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** app/controllers/concerns/shipit/authentication.rb (L18-34)
```ruby
    private

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

**File:** app/controllers/shipit/api/base_controller.rb (L24-84)
```ruby
      before_action :authenticate_api_client

      def index
        render(json: { stacks_url: api_stacks_url })
      end

      private

      module BasicAuth
        # Workaround for https://github.com/rails/rails/pull/44610
        extend ActionController::HttpAuthentication::Basic
        extend self

        private

        def basic_credentials?(request)
          request.authorization.present? && (auth_scheme(request).downcase == "basic")
        end
      end

      def namespace_for_serializer
        nil
      end

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

      attr_reader :current_api_client

      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end

      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/models/shipit/api_client.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }

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
  end
end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

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
    end
  end
end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
