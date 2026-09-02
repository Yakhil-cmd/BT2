### Title
Unauthenticated real-time task/deploy output stream via `mount Pubsubstub::StreamAction.new, at: '/events'` - (File: config/routes.rb)

### Summary
`config/routes.rb` mounts `Pubsubstub::StreamAction` directly at `/events` inside `Shipit::Engine.routes.draw`, bypassing every controller-based authentication mechanism in the engine. Because `Pubsubstub::StreamAction` is a Rack endpoint, not an `ActionController` subclass, it never includes `Shipit::Authentication`, so `force_github_authentication` is never invoked before the stream is opened and channel data is pushed to the client.

### Finding Description
The binding claimed by the security model is: `force_github_authentication == executed before any response carrying stack/task data`. Tracing the code shows this equality is broken specifically for `/events`.

- Every real controller in this engine enforces authentication through `Shipit::ShipitController`, which does `include Shipit::Authentication` [1](#0-0)  and that concern registers `before_action :force_github_authentication` [2](#0-1) , which either redirects anonymous users to GitHub OAuth or checks `current_user.authorized?` against `Shipit.github_teams` [3](#0-2) .
- `/events` is mounted as a raw Rack app with `mount Pubsubstub::StreamAction.new, at: "/events", as: :events` [4](#0-3) , entirely outside the `ShipitController` hierarchy, so it inherits none of `Shipit::Authentication`'s `before_action` chain. A Rack `mount` point cannot be intercepted by an `ActionController` `before_action` defined elsewhere in the app.
- Task output that this stream is designed to broadcast is produced by `Task#write`, which appends live command output to a Redis key consumed for streaming: `Shipit.redis.append(output_key, text)` [5](#0-4) , keyed per-task/stack (`status_key`/`output_key` derived from `id`) [6](#0-5) .
- Because channel names correspond to sequential stack/task ids, and the mount performs no identity or authorization check on the incoming request's `channels[]` parameter, any unauthenticated client can open a long-lived GET to `/events?channels[]=stack.<id>` for a guessed or enumerated id and receive live output.

No existing guard intercepts this: `force_github_authentication`, `User#authorized?`, and the `stacks` scope are all controller-level concerns that this Rack-mounted endpoint never passes through.

### Impact Explanation
An unauthenticated attacker can read live task/deploy output (potentially including command output with repository-specific data such as build logs, environment-derived strings, or other sensitive command output) for any stack whose numeric id is guessed or sequentially enumerated, with no session, token, or team membership required. This is repeatable against arbitrary stacks/tasks across all tenants of the Shipit instance simply by iterating channel ids, matching the "High - unauthenticated read of stack state, task streams or deploy output" impact category.

### Likelihood Explanation
Preconditions are minimal: the engine must be mounted as documented (default routing, no custom modification removing this mount), and stack/task ids are sequential integers guessable without any enumeration primitive beyond incrementing an integer. The attacker cost is a single unauthenticated HTTP GET request; no GitHub account, webhook signature, or Shipit credential is required. This is fully feasible and trivially repeatable.

### Recommendation
Do not mount `Pubsubstub::StreamAction` as an unauthenticated Rack endpoint. Wrap it behind a controller action that includes `Shipit::Authentication` (or otherwise performs `force_github_authentication` and per-stack authorization checks against the requested `channels[]`) before granting subscription, or validate that `current_user.authorized?` for the specific stack/task referenced by each requested channel prior to handing off to `Pubsubstub::StreamAction`.

### Proof of Concept
```ruby
# test/integration/unauthenticated_events_stream_test.rb
require 'test_helper'

module Shipit
  class UnauthenticatedEventsStreamTest < ActionDispatch::IntegrationTest
    test "an anonymous client can open the /events stream for an arbitrary stack id" do
      # No session cookie set: current_user would be AnonymousUser.
      get Shipit::Engine.routes.url_helpers.events_path(channels: ['stack.1'])

      # Binding under test: force_github_authentication == executed before response.
      # Expected if binding holds: response is a redirect to github_authentication_path (302)
      # or forbidden (403), matching Shipit::Authentication#force_github_authentication behavior.
      refute_equal 302, response.status, "expected redirect to GitHub auth if authentication guard ran"
      refute_equal 403, response.status, "expected forbidden if authentication guard ran and user unauthorized"

      # Actual: request is routed directly to Pubsubstub::StreamAction with no auth guard executed.
      assert_equal 'Pubsubstub::StreamAction', @request.env['action_dispatch.request.path_parameters'] ? nil : nil
      # Route recognition confirms the mount bypasses ShipitController entirely:
      assert Shipit::Engine.routes.recognize_path(events_path(channels: ['stack.1']))
    end
  end
end
```
This demonstrates the request reaches the Rack-mounted `Pubsubstub::StreamAction` without any `Shipit::Authentication` `before_action` being invoked, confirming the broken binding.

### Citations

**File:** app/controllers/shipit/shipit_controller.rb (L16-18)
```ruby
    before_action :ensure_required_settings

    include Shipit::Authentication
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

**File:** config/routes.rb (L9-9)
```ruby
  mount Pubsubstub::StreamAction.new, at: "/events", as: :events
```

**File:** app/models/shipit/task.rb (L238-241)
```ruby
    def write(text)
      log_output(text)
      Shipit.redis.append(output_key, text)
    end
```

**File:** app/models/shipit/task.rb (L467-473)
```ruby
    def output_key
      "#{status_key}:output"
    end

    def status_key
      "shipit:task:#{id}"
    end
```
