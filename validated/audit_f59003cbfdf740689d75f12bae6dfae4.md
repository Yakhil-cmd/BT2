### Title
CCMenu API token created without stack scoping grants read:stack access to every stack, not just the one requested - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` bearer token intended to authorize CCMenu ("CI Tray") monitoring of the single stack whose settings page the user is on, but the client is created without a `stack:` association. Because `ApiClient#stack_id` ends up `nil`, `Api::BaseController#stacks` resolves the token's authorized scope to `Stack.all` instead of the one stack the UI presented. This breaks the equality "stack the token authorizes == stack the URL/token touches," letting the leaked/embedded token read `read:stack`-gated data (build status, commits, merge requests, task outputs) for every stack in the deployment, not just the one the user intended to expose.

### Finding Description
`CCMenuUrlController#client` builds the token like this: [1](#0-0) 

This is analogous to the audited rounding bug: a value that is *computed and specified* (here, the intended per-stack scope, mirrored by the `stack:` scoping mechanism that exists elsewhere, e.g. the `here_come_the_walrus` fixture) is silently dropped/unused, and the resulting credential is weaker than intended, yet still gets handed out (analogous to `lastFeeCollectionTimestamp` being updated despite `sharesToMint` being 0 — the state/side effect proceeds without honoring the input that should have constrained it).

The authorization check that consumes this scope is: [2](#0-1) 

Since `current_api_client.stack_id?` is false for the CCMenu client, `stacks` resolves to `Stack.all`. `Api::CCMenuController` (and any other endpoint gated only by `read:stack`, e.g. commits, merge requests, task outputs) will then authorize the token against any `stack_id` param, not just the stack for which the URL was generated: [3](#0-2) [4](#0-3) 

The `Api::BaseController` permission model does support proper per-stack scoping — the fixture `here_come_the_walrus` demonstrates the intended pattern (`stack: shipit`) — but `CCMenuUrlController` never uses it: [5](#0-4) 

### Impact Explanation
The mismatch is exactly the "stack a token authorizes versus a stack it touches" binding called out in scope. CCMenu URLs are designed to be embedded in external, less-trusted contexts (CI dashboard tools, status boards, wikis) specifically because they expose only one stack's build status via an unauthenticated (session-less) bearer token in the query string. Because the token is unscoped, anyone who obtains that URL/token gains `read:stack` API access — build status, commit history, merge request state, and task/deploy output — for every stack managed by the Shipit instance, not just the one intended. This matches the High-impact category "unauthenticated read of stack state, task streams or deploy output" via a token that authorizes escalation across `Shipit.github_teams`-controlled stacks beyond what was intended for that endpoint.

### Likelihood Explanation
Likelihood is high for any deployment that uses the CCMenu feature: every time a user with access to at least one stack's settings page clicks "Fetch URL," a stack-unscoped token is created (or reused, via `find_or_create_by!(creator:, name:)`), and it is designed to be shared/embedded externally. No special privileges beyond normal Shipit login are needed to trigger the bug — only the intended narrow exposure is violated.

### Recommendation
Scope the `ApiClient` created in `CCMenuUrlController#client` to the specific stack being requested, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack:)`, and ensure lookup/reuse is also keyed by `stack_id` (not just `creator`/`name`) so a single client isn't shared/reused across stacks with an effectively global scope.

### Proof of Concept
1. As an authenticated Shipit user, visit `Stack A`'s settings page and click "Fetch URL" for CCMenu; this returns a URL containing an `ApiClient` token (`GET /ccmenu/*stack_id`).
2. Inspect the created `ApiClient` record: `stack_id` is `nil` and `permissions` includes `read:stack`.
3. Use that same token against `GET /api/stacks/*stack_id/ccmenu` (or `commits`, `merge_requests`, `tasks/:id/output`) with `stack_id` set to `Stack B` (any other stack in the instance). Because `BaseController#stacks` returns `Stack.all` for a client with no `stack_id`, the request succeeds and returns `Stack B`'s data, even though the token was only ever meant to authorize `Stack A`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
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

**File:** config/routes.rb (L27-44)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
      resources :tasks, only: %i[index show] do
        resource :output, only: :show
        member do
          put :abort
        end
      end
      resources :deploys, only: %i[index create] do
        resources :release_statuses, only: %i[create]
      end
      resources :rollbacks, only: %i[create]
      resources :commits, only: %i[index]
      resources :merge_requests, only: %i[index show update destroy]
      post '/task/:task_name' => 'tasks#trigger', as: :trigger_task
      resources :hooks, only: %i[index create show update destroy]
    end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
