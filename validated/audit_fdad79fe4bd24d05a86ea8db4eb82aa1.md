### Title
CCMenu token authorization bypass: `read:stack`-scoped `ApiClient` can read any stack's build/deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via its `stack_id` column, and `Api::BaseController#stack` enforces that scope by resolving stacks through `stacks.from_param!`, which filters to `Stack.where(id: current_api_client.stack_id)` whenever a client is stack-scoped. `Api::CCMenuController` overrides `stack` to bypass this scoping entirely, breaking the binding "stack a token authorizes == stack the token can touch."

### Finding Description
`Api::BaseController` defines the trust boundary between a token's authorized stack and the stack it can act on: [1](#0-0) 

`current_api_client.stack_id?` gates whether the client is restricted to one stack; if so, `stacks` (and therefore `stack`) is limited to that single record.

`Api::CCMenuController`, however, redefines `stack` independently, calling `Stack.from_param!(params[:stack_id])` directly instead of delegating to the inherited `stacks.from_param!`: [2](#0-1) 

`Stack.from_param!` performs an unscoped, global lookup by owner/name/environment param, with no reference to `current_api_client.stack_id`. The controller only enforces the coarse-grained `read:stack` permission via `require_permission :read, :stack`, which checks the permission string, not the specific stack the token is bound to. It also supports token authentication straight from the query string, independent from cookie-based session auth, via its own `authenticate_api_client` override that calls `ApiClient.authenticate(params[:token])` directly — matching the documented use case of embedding a per-stack CCMenu URL/token (see `Api::CcmenuUrlController#client`, which creates tokens scoped with `permissions: %w[read:stack]`).

As a result, any valid `ApiClient` token with `read:stack` permission — even one deliberately scoped to a single stack (`api_client.stack_id` set) — can be pointed at an arbitrary `stack_id` in the CCMenu URL and will successfully render that other stack's build/deploy status, because the controller-level `stack` lookup never consults the token's `stack_id` scope.

### Impact Explanation
This breaks the binding "a stack a token authorises versus a stack it touches." It grants unauthorized cross-stack read access to stack state and deploy status/output (last deploy status, lock state, running task info) for any stack in the installation, using a token that was explicitly provisioned to be limited to one stack. This matches the High-impact category of "unauthenticated read of stack state, task streams or deploy output" in spirit — the token holder is authenticated for one narrow scope but can read data for stacks entirely outside their authorization.

### Likelihood Explanation
Low-to-Moderate. It requires possession of any valid API token bearing `read:stack` permission (these are routinely distributed as CCMenu URLs embedded in CI dashboards, which are far more widely shared/leaked than admin credentials) and knowledge of, or guessing, another stack's identifier (owner/repo/environment), which is often discoverable via the Shipit UI itself. No `webhook_secret`, `api_clients_secret`, GitHub credentials, or privileged account are needed — only a legitimately-issued, narrowly-scoped `read:stack` token.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or make it call the inherited scoped `stacks.from_param!`) so that stack-scoped tokens cannot resolve stacks outside their `stack_id`. Apply the same scoped lookup used by `Api::BaseController#stack` universally, and add a regression test asserting that a token scoped to stack A returns `404`/`403` when `stack_id` in the request refers to stack B.

### Proof of Concept
1. Admin creates (or the app auto-creates via `CCMenuUrlController#fetch`) an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, stack: stack_a, permissions: %w[read:stack])`, yielding `token_A`.
2. Attacker (or leaked-URL holder) sends: `GET /api/<stack_b_owner>/<stack_b_name>/<stack_b_env>/ccmenu.xml?token=<token_A>`.
3. `authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because the client has the `read:stack` permission string, regardless of `stack_id`.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])`, returning Stack B — not Stack A — and Stack B's `deploys_and_rollbacks.last` status is rendered in the XML response, disclosing Stack B's deploy state to a token never authorized for Stack B. [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
