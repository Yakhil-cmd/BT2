### Title
CCMenu API client tokens are never scoped to the stack they were issued for, so a leaked token grants read access to every stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
Shipit issues a per-stack "CCMenu" polling URL that embeds an `ApiClient` authentication token in the query string. The token is intended to authorize read access to the single stack the URL was generated for, but neither the token itself nor the controller that consumes it enforce that scope, so the token actually authorizes read access to *any* stack.

### Finding Description
`CCMenuUrlController#client` creates the API client used for CCMenu polling without ever assigning `stack_id`: [1](#0-0) 

The generated URL only carries the stack in the path/`stack_id` param, and the token in the query string: [2](#0-1) 

The consuming endpoint, `Api::CCMenuController`, requires only the generic `read:stack` permission (not "read this specific stack"), authenticates the API client from the raw `token` query param, and then resolves the target stack directly from `params[:stack_id]` via `Stack.from_param!`, completely bypassing the stack-scoping helper (`stacks`) that `Api::BaseController` normally uses to restrict a scoped `ApiClient` to its own stack: [3](#0-2) 

Compare with the intended scoping mechanism in the base controller, which is supposed to bind an `ApiClient.stack_id` to the set of stacks it can touch: [4](#0-3) 

`CCMenuController#stack` overrides this and reads `params[:stack_id]` unconditionally: [5](#0-4) 

The binding that should hold is: `stack the token authorizes == stack the request touches`. Before: the token is minted for stack A and the URL path encodes stack A. After: because the `ApiClient` row created for CCMenu never has `stack_id` set, and the controller ignores the `stacks` scoping helper entirely, the same `read:stack` token can be replayed against `api/stacks/<any-stack-id>/cc_menu.xml?token=...` for every stack in the installation. This is directly analogous to the audited pattern in the external report, where an accounting/authorization variable (`trackedCvxBalance`) was updated/consulted inconsistently with the operation actually performed, breaking the invariant the code was supposed to enforce — here the invariant "token authorizes exactly one stack" is never actually implemented or enforced anywhere in the code path.

### Impact Explanation
Any party who obtains a CCMenu token (these tokens are long-lived, embedded in plaintext URLs typically configured into third-party CI dashboard/build-monitor tools, and thus prone to leaking via browser history, `Referer` headers, proxy/access logs, or shared dashboards) gains `read:stack` access to the build/deploy status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of every stack in the Shipit instance, not just the one it was minted for. This is an unauthorized read of stack state across the whole installation using a credential that was only ever supposed to authorize a single stack — an escalation of the token's intended authorization scope.

### Likelihood Explanation
No privileged access is required beyond obtaining a single, already-issued CCMenu token (which is explicitly designed to be shared with external tooling and embedded in a URL, i.e., a low-trust, easily-leaked credential). Once obtained, exploitation is a single unauthenticated HTTP GET with a different `stack_id`; there is no additional secret, signature, or check to bypass.

### Recommendation
Set `stack_id: stack.id` when creating the `ApiClient` in `CCMenuUrlController#client`, and change `Api::CCMenuController#stack` to reuse the inherited `stacks` scoping helper (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so a CCMenu token can only ever resolve the stack it was scoped to.

### Proof of Concept
1. As a logged-in user, request `GET /stacks/:stack_a/ccmenu_url` to obtain a CCMenu URL/token intended for stack A: `.../api/stacks/stack_a/cc_menu.xml?token=<TOKEN>`. [6](#0-5) 
2. Obtain `<TOKEN>` (e.g., via a leaked build-monitor config, proxy log, or browser history).
3. Replay the same token against a different stack: `GET /api/stacks/stack_b/cc_menu.xml?token=<TOKEN>`.
4. `Api::CCMenuController#authenticate_api_client` validates the token via `ApiClient.authenticate`, `require_permission :read, :stack` only checks the generic permission string, and `#stack` resolves `stack_b` directly — the response renders stack B's build status even though the token was minted only for stack A. [7](#0-6)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-12)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```
