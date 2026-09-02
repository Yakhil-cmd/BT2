### Title
CCMenu API token created without a `stack_id` grants global `read:stack` access instead of the single-stack scope the URL implies - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

### Summary
The HTLC bug hinges on a mismatch between the scope an actor is entitled to (their own timelock/tokens) and the scope they can actually act on (the counterparty's shorter-lived lock). The engine analog is a mismatch between the stack an `ApiClient` token is supposed to authorize (the single stack named in the CCMenu URL) and the stack(s) it actually touches (every stack in the installation).

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` for the current user without ever assigning `stack:`: [1](#0-0) 

Because `stack_id` is never set, `ApiClient#stack_id?` is false. `Api::BaseController#stacks` therefore falls back to `Stack.all` rather than restricting the client to the one stack the URL was generated for: [2](#0-1) 

`Api::CCMenuController` compounds this by overriding `stack` to call `Stack.from_param!(params[:stack_id])` directly — completely bypassing the `stacks` scoping helper that would enforce a per-client stack restriction even if one had been set: [3](#0-2) 

`ApiClient#check_permissions!` only checks the coarse `read:stack` string, with no per-stack binding at all: [4](#0-3) 

The binding that should hold is: `{stack authorized by CCMenu token} == {stack the token can query via /api/*/ccmenu}`. Because `CCMenuUrlController#client` never sets `stack:`, and `CCMenuController#stack` re-fetches by arbitrary `params[:stack_id]` param, the equality breaks: the token authorizes (in principle) one stack but touches all stacks, for any `stack_id` value supplied in the request path.

### Impact Explanation
A `CCMenu` token is deliberately designed to be embedded in a bare URL (`ccmenu_url`) intended for consumption by third-party CI-status widgets/desktop apps outside the normal authenticated Shipit session — i.e., it is meant to be a narrowly-scoped, leak-tolerant credential for exactly one stack. Anyone who obtains a single such URL/token (via logs, shared dashboards, browser history, a CI widget config file, etc.) can instead call `GET /api/*/ccmenu?token=...` for **every other stack** in the installation and receive `lastBuildStatus`, `activity` (running/sleeping), `lastBuildLabel` (deploy id), and `webUrl` for stacks they were never meant to see. This is an unauthenticated (session-less) read of stack state across repositories, matching the "High - unauthenticated read of stack state" impact category.

### Likelihood Explanation
No privileged action beyond obtaining one leaked CCMenu token is required; the token holder does not need a Shipit session, GitHub credentials, or the `api_clients_secret`. Any stack name/slug is guessable or discoverable via `/repositories`, `/stacks` indexes, or public GitHub repo names, since `Stack.from_param!` resolves stacks by their public path (`owner/repo/environment`). This makes exploitation straightforward once a single token leaks — a realistic and common occurrence for URLs meant to be embedded in status widgets.

### Recommendation
- Set `stack:` when creating/finding the CCMenu `ApiClient` in `CCMenuUrlController#client`, so `stack_id?` is true and the client is scoped to a single stack.
- Remove `CCMenuController`'s override of `#stack` (or make it delegate to the inherited `stacks.from_param!`) so per-client stack scoping is enforced even for this controller.
- Consider making `ApiClient#check_permissions!`/`stacks` enforcement mandatory (fail closed) whenever `stack_id` is `nil` for tokens created via non-admin, narrowly-scoped flows like CCMenu.

### Proof of Concept
1. As an authenticated Shipit user, visit `/ccmenu/*stack_id` for `stack-a` (e.g. `acme/app/production`) to obtain a CCMenu URL: `GET /api/acme/app/production/ccmenu?token=T`.
2. `CCMenuUrlController#client` creates (or reuses) an `ApiClient` named "CCMenu Client" for this user with `permissions: ['read:stack']` and no `stack_id`.
3. An attacker who obtains `T` (from a leaked widget config, log, or shared screen) sends `GET /api/acme/other-secret-app/production/ccmenu?token=T`.
4. `Api::CCMenuController#authenticate_api_client` authenticates `T` successfully; `require_permission :read, :stack` passes because the permission check is not stack-specific; `#stack` calls `Stack.from_param!(params[:stack_id])` directly, returning `other-secret-app`'s stack regardless of the token's intended scope.
5. The attacker receives `other-secret-app`'s deploy status, activity, last build label, and URL — data for a stack they were never granted access to. [5](#0-4) [6](#0-5) [2](#0-1)

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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
