### Title
CCMenu API token is not bound to the stack it was generated for, allowing cross-stack disclosure of deploy status - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
The `CCMenuUrlController#fetch` action mints a long-lived `ApiClient` token intended to authorize read-only CCMenu access to a single stack, but the token it creates is never bound to that stack, and the consuming `Api::CCMenuController` never checks that the requested `stack_id` matches any stack scope on the token. The binding the system relies on — "the stack a URL/token was issued for" == "the stack the token is accepted for" — does not hold.

### Finding Description
`CCMenuUrlController#fetch` builds a shareable CCMenu URL and embeds an `ApiClient` authentication token in its query string: [1](#0-0) 

The client is obtained via:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
`find_or_create_by!` only matches/searches on `creator` and `name` — the `stack` for which the URL was requested is never persisted on the `ApiClient` (there is no `stack:` attribute passed to `create_with`, and `ApiClient#stack` is `optional: true`): [2](#0-1) 

As a result, this is a single, unscoped, per-user "CCMenu Client" reused across every stack the user requests a CCMenu URL for, and it carries no `stack_id`.

The consuming endpoint, `Api::CCMenuController`, only requires the generic `read:stack` permission and resolves the target stack directly from the request parameter, bypassing the stack-scoping mechanism used elsewhere in the API: [3](#0-2) 

Contrast this with the standard, correctly-scoped pattern used by every other API controller (`Api::StacksController`, `Api::TasksController`, `Api::HooksController`, etc.), which resolves the stack through `BaseController#stacks`, restricting results to `current_api_client.stack_id` when the client is stack-bound: [4](#0-3) 

`Api::CCMenuController` overrides `authenticate_api_client` to accept the token from `params[:token]` instead of `Authorization`, but overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly — never consulting `current_api_client.stack_id` (which, per the analysis above, is always `nil` for this client type anyway): [5](#0-4) 

The equality that breaks is: **stack the token/URL was authorized for `stack_id_A`** ≠ **stack the token is actually accepted to read `stack_id_B` (any stack, since `stack_id` is attacker-controlled in the URL and the client carries no stack restriction)**.

### Impact Explanation
Any holder of a single CCMenu URL/token — these are designed to be pasted into third-party desktop CI-status menu bar applications and are explicitly rendered in plaintext, e.g. shared over chat/CI dashboards — can substitute any other stack's identifier in the `stack_id` path segment and retrieve that stack's deploy/build status (`latest_deploy`, `running?`, `ended_at`) via `Api::CCMenuController#show`, without ever being a member of the corresponding GitHub team or having been granted access to that stack. This is an unauthenticated (session-less) read of stack/deploy state gated only by permission-scope name (`read:stack`) rather than the specific stack the credential was meant to be limited to, matching the "unauthorized read of stack state / deploy output" High-impact category.

### Likelihood Explanation
No privileged Shipit session, GitHub token, or webhook secret is required — only knowledge of one leaked/shared CCMenu URL (which by design is meant to be shared with lightweight external tooling) plus the ability to enumerate or guess another stack's `stack_id` (stack ids/slugs are visible throughout the Shipit UI, e.g. `owner/repo/environment`). No signature, MAC, or stack claim inside the token restricts it — the token only encodes the `ApiClient` row id via `SimpleMessageVerifier`, and permission checking never re-validates the stack.

### Recommendation
Bind the generated `ApiClient` to the specific stack (`stack: stack`) when creating it in `CCMenuUrlController#client`, and make `Api::CCMenuController#stack` resolve through the same stack-scoped lookup used elsewhere (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, then `.from_param!`), instead of resolving `Stack.from_param!(params[:stack_id])` unconditionally.

### Proof of Concept
1. As an authorized Shipit user, visit `stacks/*id` and click to fetch the CCMenu URL, e.g. via `GET /ccmenu_url/*owner/repo/environment`, receiving `.../api/*owner/repo/environment/ccmenu.xml?token=<T>`.
2. Take `<T>` and request a different stack's status: `GET /api/*other-owner/other-repo/other-environment/ccmenu.xml?token=<T>`.
3. Because `Api::CCMenuController#authenticate_api_client` accepts `<T>` (it's a valid, unscoped `ApiClient`) and `#stack` resolves purely from `params[:stack_id]`, the response returns the *other* stack's deploy status, disclosing data for a stack never granted to that token/URL holder.

### Citations

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

**File:** app/models/shipit/api_client.rb (L1-21)
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

**File:** app/controllers/shipit/api/base_controller.rb (L65-80)
```ruby
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
```
