### Title
CCMenu API token is not stack-scoped and the CCMenu API endpoint ignores `ApiClient` stack scoping - ([File: app/controllers/shipit/ccmenu_url_controller.rb], [File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The bug-class from the report ("gathered value is tracked by one mechanism but withdrawn/consumed through another path that doesn't check that mechanism's restriction") maps to a concrete authorization-scope gap in Shipit's CCMenu integration: an `ApiClient` token that a user believes is scoped to a single stack's CI status is actually usable to read the deploy status of *any* stack in the installation.

### Finding Description
`Shipit::ApiClient` supports per-token stack scoping via the optional `stack` association, and `Api::BaseController` is written to respect it: [1](#0-0) 

However, `CCMenuUrlController#client`, which mints the token embedded in the "CCMenu URL" a user copies from a stack's settings page, creates the `ApiClient` **without** setting `stack:`, and reuses the *same* record (`find_or_create_by!(creator: current_user, name: 'CCMenu Client')`) regardless of which stack's URL was requested: [2](#0-1) 

Because `stack` is never set, `ApiClient#stack_id?` is false for this token, so it is treated as global (`Stack.all`) rather than scoped to the one stack the URL was generated for. On top of that, `Api::CCMenuController` doesn't even go through the scoped `stacks`/`stack` helper from `BaseController` — it overrides `stack` to resolve `Stack.from_param!(params[:stack_id])` directly, bypassing any stack restriction entirely: [3](#0-2) 

The binding that should hold is: `stack the token authorises == stack the request touches`. In this code path that equality is broken twice — first because the token itself is never bound to a stack, second because the controller consuming it never checks the bound stack even when one exists.

### Impact Explanation
Any user who generates a "CCMenu URL" for one stack (a normal, low-privilege UI action available to any authenticated Shipit user with `read:stack` visibility of that one stack) obtains a `read:stack` token that can be replayed against `GET /api/stacks/:any_stack_id/ccmenu` for every stack in the Shipit installation, disclosing deploy/rollback identifiers, timestamps and running/success/failure status for stacks the user was never authorized to see. This is an authorization-scope escalation matching "High - escalation into `Shipit.github_teams` authorization... unauthenticated read of stack state" since a token intended for one stack's status page becomes a read credential for the whole instance. The `CCMenuController#show` route is reachable with only a bare `token` query parameter, no session or `X-Shipit-User` header, so any party who obtains this URL (network logs, browser history, a shared CI dashboard config, referer leakage) inherits the same over-broad access.

### Likelihood Explanation
No special privilege is required beyond the ability to open the settings page of any single stack and fetch its CCMenu URL, which is intended to be given to third-party CI dashboard tooling (CCMenu-compatible clients) — i.e., these tokens are designed to be pasted into external, less-trusted systems. Because the same `ApiClient` record is reused for a given user (`find_or_create_by!` keyed only on `creator` and `name`), a single leaked token, once obtained, works against all stacks without further code execution.

### Recommendation
- Set `stack:` when creating/looking up the "CCMenu Client" `ApiClient` in `CCMenuUrlController#client`, scoping `find_or_create_by!` by `creator`, `name`, and `stack` so each stack gets its own token.
- In `Api::CCMenuController#stack`, use the inherited scoped `stacks` helper (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped token cannot be replayed against a different `stack_id`.

### Proof of Concept
1. User A opens Stack A's settings page and requests its CCMenu URL; `CCMenuUrlController#fetch` calls `client` which creates (or reuses) an `ApiClient` named "CCMenu Client" for User A with `permissions: ['read:stack']` and no `stack` set, then returns `.../api/stacks/<A>/ccmenu?token=T`. [4](#0-3) 
2. This URL/token `T` is pasted into an external CI dashboard tool as intended.
3. Anyone with access to `T` sends `GET /api/stacks/<B>/ccmenu?token=T` for an arbitrary stack `B` that User A has never been authorized to view.
4. `CCMenuController#authenticate_api_client` accepts `T` via `ApiClient.authenticate(params[:token])`, `require_permission :read, :stack` passes because `T` has `read:stack`, and `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly (no scoping check), returning Stack B's deploy status in the XML response. [5](#0-4)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-23)
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
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-36)
```ruby
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
