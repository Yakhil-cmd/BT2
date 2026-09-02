### Title
Unauthenticated read of `/events?channels=stack.ID` via `mount Pubsubstub::StreamAction.new` bypassing `Shipit::Authentication` - ([File: config/routes.rb])

### Summary
`config/routes.rb` mounts `Pubsubstub::StreamAction.new` directly as a Rack endpoint at `/events`, bypassing Rails controller filters entirely. `Shipit::Authentication#force_github_authentication` is a `before_action` included only in `Shipit::ShipitController` (via `Shipit::Authentication`), and never runs for a `mount`-ed Rack app, so the engine itself provides no authentication for `/events`.

### Finding Description
The claimed binding is: `every SSE response served at /events` == `response produced after force_github_authentication passed (== true)`. Tracing the code shows this binding does not hold inside the engine.

- `config/routes.rb:9` — `mount Pubsubstub::StreamAction.new, at: "/events", as: :events` mounts a raw Rack endpoint, not an `ActionController` action. [1](#0-0) 
- `Shipit::Authentication#force_github_authentication` is wired only via `include Shipit::Authentication` inside `Shipit::ShipitController`, and applies to controllers inheriting from it (as a Rails `before_action`). [2](#0-1) [3](#0-2) 
- Because `Pubsubstub::StreamAction` is mounted directly (not dispatched through `ShipitController`/`ApplicationController`), Rails `before_action` filters never run for requests to `/events`; there is no `before_action` or `Shipit::Authentication` concern in front of it within this engine.
- The engine's own comment acknowledges this gap explicitly: `github_authentication_controller.rb` states "/events and /sidekiq endpoint... leverage `UserRequiredMiddleware`" for protection — but `UserRequiredMiddleware` is not defined, required, or inserted anywhere in this engine (`lib/shipit/engine.rb` initializers only add `OmniAuth::Builder` and `Shipit::SameSiteCookieMiddleware`, no user-required middleware). [4](#0-3) [5](#0-4) 
- The channel names are predictable/enumerable integer stack IDs, e.g. `events_path(channels: ["stack.#{@stack.id}"])`, consistently used across views to subscribe to live SSE updates for deploy status transitions. [6](#0-5) [7](#0-6) 
- Live events streamed on `stack.<id>` include deploy/task status transitions, e.g. `Stack#broadcast_update` publishing to `Pubsubstub` on the `stack.#{id}` channel, and status/commit updates publishing on the same channel pattern. [8](#0-7) [9](#0-8) 

Existing guards that were checked and do not prevent this:
- `force_github_authentication` — never invoked for this Rack-mounted route; guard is inapplicable, not bypassed via a flaw in its logic, but structurally absent from the request path. [10](#0-9) 
- `UserRequiredMiddleware` — referenced only in a code comment; not implemented or configured by the engine (`lib/shipit/engine.rb`), so it cannot be relied upon as an engine-level control; it is a host-app responsibility that this engine does not enforce, verify, or even ship. [4](#0-3) 

Attacker request: an unauthenticated `GET /events?channels=stack.1` (or any guessed/enumerated numeric stack ID) reaches `Pubsubstub::StreamAction` directly with no engine-level authentication check, and the endpoint will serve the SSE stream for that channel if the host application does not itself add an equivalent guard around the mount point.

### Impact Explanation
If the host app does not add its own middleware/before_action for `/events` (which the engine's own routes and initializers do not do, and only a code comment gestures at as an external expectation), an unauthenticated attacker gains a live read-only feed of stack/task state changes — deploy status transitions, commit updates, lock changes — for any stack ID they can enumerate, across every stack/tenant hosted by that Shipit instance. This matches the "High - unauthenticated read of stack state, task streams or deploy output" category. It does not permit any write, RCE, or credential exfiltration, so it is not Critical.

### Likelihood Explanation
Exploitability from the engine's own code requires no secrets, no session, and no privileged role — a bare `GET /events?channels=stack.<id>` with guessed/incrementing integer IDs. The severity of the actual live deployment is contingent on host-app configuration (whether the host wires up `UserRequiredMiddleware` or equivalent around `/events`), since the engine's `config/routes.rb`, `lib/shipit/engine.rb`, and `Shipit::Authentication` concern provide no enforcement themselves. Within this engine's code alone, the mount point is unauthenticated by construction.

### Recommendation
Do not rely on a documentation comment referencing a host-provided `UserRequiredMiddleware`. Instead, wrap the `/events` mount with an engine-owned authentication guard, e.g. mount `Pubsubstub::StreamAction` behind a small Rack middleware/constraint that itself checks `session[:user_id]`/`current_user.authorized?` (mirroring `Shipit::Authentication#force_github_authentication`), or move the SSE endpoint behind an actual `ActionController` action that includes `Shipit::Authentication`, and additionally validate that the requested `channels` correspond to stacks the current user is authorized to view.

### Proof of Concept
```ruby
# test/integration/events_stream_authentication_test.rb (minitest, no live GitHub)
require 'test_helper'

module Shipit
  class EventsStreamAuthenticationTest < ActionDispatch::IntegrationTest
    test "GET /events without a session is not rejected by an engine-level authentication guard" do
      stack = shipit_stacks(:shipit)

      # No session[:user_id], no session[:authenticated] set.
      get "/events", params: { channels: "stack.#{stack.id}" }

      # Binding under test: response produced only if force_github_authentication ran and passed.
      # Assert engine did not redirect to github_authentication_path nor render 403,
      # which is what Shipit::Authentication#force_github_authentication would do.
      refute_redirected_to Shipit::Engine.routes.url_helpers.github_authentication_path
      refute_equal 403, response.status
      # Pubsubstub::StreamAction responds with SSE content-type/status when reached unauthenticated.
      assert_match(/text\/event-stream/, response.content_type.to_s)
    end
  end
end
```
This demonstrates that, purely within the engine's own routing and controller stack, no `before_action`/`Shipit::Authentication` check intercepts `/events`, confirming the equality `SSE response served == force_github_authentication passed` is false for this route.

### Citations

**File:** config/routes.rb (L9-9)
```ruby
  mount Pubsubstub::StreamAction.new, at: "/events", as: :events
```

**File:** app/controllers/concerns/shipit/authentication.rb (L7-10)
```ruby
    included do
      before_action :force_github_authentication
      helper_method :current_user
    end
```

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

**File:** app/controllers/shipit/shipit_controller.rb (L16-18)
```ruby
    before_action :ensure_required_settings

    include Shipit::Authentication
```

**File:** app/controllers/shipit/github_authentication_controller.rb (L15-18)
```ruby
      # We need to set this so that the /events and /sidekiq endpoint
      # which leverage `UserRequiredMiddleware` will recognize the user
      # is authenticated.
      session[:authenticated] = true
```

**File:** lib/shipit/engine.rb (L46-55)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
      end

      if Shipit.enable_samesite_middleware?
        app.config.middleware.insert_after(::Rack::Runtime, Shipit::SameSiteCookieMiddleware)
      end
```

**File:** app/views/shipit/stacks/show.html.erb (L1-1)
```erb
<% subscribe events_path(channels: ["stack.#{@stack.id}"]), '#layout-content' %>
```

**File:** app/views/shipit/merge_requests/index.html.erb (L1-1)
```erb
<% subscribe events_path(channels: ["stack.#{@stack.id}"]), '.pr-list', '.header' %>
```

**File:** app/models/shipit/stack.rb (L561-567)
```ruby
    def broadcast_update
      Pubsubstub.publish(
        "stack.#{id}",
        { id:, updated_at: }.to_json,
        name: 'update'
      )
    end
```

**File:** test/models/status_test.rb (L58-63)
```ruby
    def expect_event(stack)
      Pubsubstub.expects(:publish).at_least_once
      Pubsubstub.expects(:publish).with do |channel, _payload, options = {}|
        options[:name] == 'update' && channel == "stack.#{stack.id}"
      end
    end
```
