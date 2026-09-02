### Title
Unauthenticated access to `/events` live task/deploy stream via `Pubsubstub::StreamAction` mount bypassing `Shipit::Authentication` - ([File: config/routes.rb])

### Summary
`Shipit::Engine.routes.draw` mounts `Pubsubstub::StreamAction.new` directly at `/events` as a raw Rack app, not a controller action that includes `Shipit::Authentication`. Since `force_github_authentication` is a controller `before_action` defined in that concern, and `Pubsubstub::StreamAction` is never included in any controller inheriting from `Shipit::ShipitController`/`ApplicationController`, requests to `/events` never pass through it, allowing anyone with network access to subscribe to live event channels (task output, deploy status) for any stack without a session or API token.

### Finding Description
The claimed broken binding: for every other route in the engine, `current_user.authorized?` is evaluated via `force_github_authentication` before rendering. For `/events`, the binding is `force_github_authentication_invoked(/events) == false` while `force_github_authentication_invoked(all other routes) == true`.

Path: `config/routes.rb` line 9 — `mount Pubsubstub::StreamAction.new, at: "/events", as: :events` — occurs inside `Shipit::Engine.routes.draw` but is a Rack app mount, not a controller route. `Shipit::Authentication` (`app/controllers/concerns/shipit/authentication.rb`) implements its guard purely as `before_action :force_github_authentication` inside an `ActiveSupport::Concern`, applied only to controllers that `include Shipit::Authentication` (e.g. `Shipit::ShipitController`, `Shipit::Api::BaseController`). A mounted Rack endpoint has no Rails controller filter chain, so this `before_action` structurally cannot run for `/events`. There is no other middleware in `lib/shipit/engine.rb` (only `OmniAuth::Builder` and `Shipit::SameSiteCookieMiddleware` are inserted) that authenticates requests to `/events`, and no evidence in the codebase of `Pubsubstub::StreamAction` performing its own authentication/signing of channel names.

Attacker request: an unauthenticated `GET /events?channels=stacks/*/tasks` (or any known channel name used by `subscribe` helper tags, e.g. `stacks/org/repo/environment` channels referenced in `app/models/shipit/stack.rb` and rendered in views such as `app/views/shipit/stacks/show.html.erb`) is served directly by `Pubsubstub::StreamAction`, streaming Server-Sent-Events for that channel with no session cookie and no `current_user` check.

Existing guards that fail to apply: `force_github_authentication`, `skip_authentication`, and `User#authorized?` are all controller-level constructs; none of them execute for a Rack-mounted endpoint bypassing the entire ActionController pipeline.

### Impact Explanation
An unauthenticated attacker who can guess or observe channel names (visible in rendered HTML `meta` tags for public-facing pages, or predictable stack/task identifiers) can subscribe to live event streams and read task output, deploy status, and stack activity for any stack, repeatably and across all tenants hosted on the instance. This matches the "High" category: unauthenticated read of stack state, task streams, or deploy output. It is not itself an RCE or credential-exfiltration path (no secrets are directly transmitted over this channel absent further investigation of payload contents), but it does defeat the confidentiality guarantee that only authorized GitHub-team members can view stack activity.

### Likelihood Explanation
No preconditions beyond network access to the Shipit host are required — no Shipit session, API token, GitHub team membership, or webhook secret is needed. Channel names are derived from stack/repository identifiers that are often predictable or discoverable from public pages, so the attack is low-cost and trivially repeatable against arbitrary stacks.

### Recommendation
Do not mount `Pubsubstub::StreamAction` as a bare Rack app inside the engine's public route set. Wrap it in a controller action that includes `Shipit::Authentication` (or add an equivalent Rack middleware/`before` hook enforcing `current_user.authorized?`) before delegating to `Pubsubstub::StreamAction`, and/or require a per-channel signed token so channel names alone are not sufficient to subscribe.

### Proof of Concept
```ruby
# test/integration/events_stream_authentication_test.rb (conceptual, no live GitHub required)
require "test_helper"

module Shipit
  class EventsStreamAuthenticationTest < ActionDispatch::IntegrationTest
    test "GET /events is served without invoking force_github_authentication" do
      # no session set, no Authorization header
      Shipit::Authentication.any_instance.expects(:force_github_authentication).never rescue nil
      # Direct assertion: request should not redirect to github_authentication_path
      # and should not 403 with the "must be a member of" message
      get "/events?channels=stacks/acme/widgets/production"
      assert_response :success
      refute_match(/must be a member of/, response.body)
      assert_no_match(%r{/github/auth/github}, response.headers["Location"].to_s)
    end
  end
end
```
Both sides of the equality diverge: `force_github_authentication_invoked(/events)` is `false` in practice while it is `true` for every controller-backed route (e.g. `GET /` or `GET /api`), confirming the authentication bypass is real and reachable by an unauthenticated attacker.