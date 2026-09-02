### Title
Authorization scope bypass: stack-scoped API token can read the CI status of any stack via `CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` binds every stack-scoped `ApiClient` to the single stack it was created for by routing all stack lookups through the scoped `stacks` relation [1](#0-0) . `Shipit::Api::CCMenuController`, however, overrides `#stack` to look the stack up directly from the global `Stack` table, completely skipping the client's `stack_id` binding [2](#0-1) . A token that was only ever granted `read:stack` on one stack can therefore be replayed with a different `stack_id` to read another stack's build/deploy status.

### Finding Description
`ApiClient` records can optionally be scoped to a single stack (`belongs_to :stack, optional: true`) [3](#0-2) . Every "normal" API controller resolves the target stack through `Api::BaseController#stack`, which is built on top of `#stacks`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

This is the equality that is supposed to hold: `requested stack ∈ {stacks authorized by current_api_client.stack_id}`. `require_permission!` only checks that the *operation:scope* pair (e.g. `read:stack`) is present in `permissions` [4](#0-3)  — it never checks which specific stack the token is bound to. That binding is enforced purely by scoping the `Stack` lookup through `#stacks`.

`CCMenuController` breaks this equality by re-implementing `#stack` to bypass the scope entirely:

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end

  def authenticate_api_client
    @current_api_client = ApiClient.authenticate(params[:token])
    super unless @current_api_client
  end
end
``` [5](#0-4) 

`require_permission :read, :stack` merely verifies the token has `read:stack` in its `permissions` array; it does not verify that `params[:stack_id]` matches `current_api_client.stack_id`. Because `#stack` here queries the unscoped `Stack` model directly (`Stack.from_param!`, not `stacks.from_param!`), any token carrying `read:stack` — even one created and intended for exactly one stack — can be replayed against an arbitrary `stack_id` to fetch that other stack's CCMenu status (`stack.deploys_and_rollbacks.last`, latest build status/label/time, lock status) [6](#0-5) .

This is directly comparable to the H-3 pattern: the code verifies one part of the trust equation (`operation:scope` permission exists) while the second, equally required part of the check (`stack ∈ token's authorized scope`) is silently absent for this one controller, even though the surrounding framework (`BaseController#stacks`) implements it correctly for every other endpoint.

Compounding this, `CCMenuUrlController#fetch` — the normal way these tokens are minted — creates an `ApiClient` with `permissions: %w[read:stack]` but does **not** set `stack:` on it at all [7](#0-6) , and memoizes it per-user (`find_or_create_by!(creator: current_user, name: 'CCMenu Client')`), so the same token is reused across every stack that user requests a CCMenu URL for. `CCMenuController#authenticate_api_client` explicitly supports authenticating purely from a `token` query-string parameter with no session required [8](#0-7) , which is the intended design so that these URLs can be embedded in third-party CI dashboards/badges without a login. Since the token is unscoped and the controller doesn't enforce stack scoping either way, anyone who obtains one such shared CCMenu URL (e.g., pasted into a public README, chat channel, or external CI aggregator — the explicit purpose of the feature) can swap `stack_id` in the URL to read the build/deploy status of any other stack in the Shipit instance, including private/internal ones, without needing a Shipit login, an admin-issued API token, or any other privileged credential.

### Impact Explanation
This is an authorization-scope bypass allowing unauthenticated (session-less) disclosure of another stack's deploy/build/task state through a token that was only ever supposed to grant read access to one specific stack. That matches "High - ... unauthenticated read of stack state, task streams, or deploy output" in the impact taxonomy: the CCMenu token, designed to be shared externally for exactly one stack, becomes a master key for reading any stack's CI/deploy status.

### Likelihood Explanation
The bug is directly reachable with no privileged credentials: any holder of a single, intentionally-shareable CCMenu URL (the entire point of the `CCMenuUrlController` feature is that these URLs are meant to be embeddable in external, non-authenticated CI dashboards) can enumerate/guess other `stack_id` values and immediately view their status. No signature/secret/session is needed to exploit it once one such URL is known — only the general public design of the feature is assumed, matching the "unprivileged-attacker, no session" baseline.

### Recommendation
Make `CCMenuController#stack` go through the scoped `stacks` helper from `Api::BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` binding is enforced exactly like every other API controller. Additionally, have `CCMenuUrlController#fetch` create/scope the `ApiClient` to the specific `stack` it was generated for (pass `stack:` into `create_with`/`find_or_create_by!`) rather than sharing one unscoped, permission-only token per user across all stacks.

### Proof of Concept
1. As any Shipit user with access to `stack_a`, visit the "CCMenu URL" feature for `stack_a`; this creates/returns a `CCMenu Client` `ApiClient` with `permissions: ['read:stack']` and no `stack_id`, and returns a URL such as `https://shipit.example.com/api/stacks/stack_a/ccmenu.xml?token=<TOKEN>` [9](#0-8) .
2. Share/paste this URL somewhere external (its intended use, per the feature).
3. An outside party who obtains that URL requests `https://shipit.example.com/api/stacks/stack_b/ccmenu.xml?token=<TOKEN>` for a completely unrelated `stack_b`.
4. `CCMenuController#authenticate_api_client` authenticates the token directly with no session [8](#0-7) , `require_permission :read, :stack` passes because the token has `read:stack`, and `#stack` resolves `stack_b` unscoped [10](#0-9) , returning `stack_b`'s build/deploy status — a stack the token was never meant to expose.

**Note on verification limits:** I was unable to complete confirmation of the exact route configuration for these controllers and whether `CCMenuUrlController` enforces a login/session requirement before minting the token (the file read for `config/routes.rb` and `app/controllers/shipit_controller.rb` did not return content in the final tool round). The core vulnerability — `CCMenuController#stack` bypassing `Api::BaseController`'s stack-scoping used everywhere else — is confirmed directly from the source shown above and does not depend on that unresolved detail.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-36)
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
