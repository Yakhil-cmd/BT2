### Title
Unauthenticated SSE subscription to arbitrary `stack.<id>`/`repository.<id>` channels via `Pubsubstub::StreamAction` mount - ([File: config/routes.rb])

### Summary
`mount Pubsubstub::StreamAction.new, at: "/events"` is wired directly into `Shipit::Engine.routes.draw` as a bare Rack endpoint, completely outside the controller stack that enforces `Shipit::Authentication`. Any unauthenticated client can send `GET /events?channels=stack.<id>` (or `repository.<id>`) and receive live SSE push notifications for that resource, with no session, API token, or team membership check.

### Finding Description
The broken binding is: `channel subscribed to on /events == a resource the requester's session (current_user) was authorized to view`. In practice, the mount has no relationship to `current_user` at all.

- `config/routes.rb:9`: `mount Pubsubstub::StreamAction.new, at: "/events", as: :events` — this is a `Rack` app mounted at the engine's route-drawing level, not a route dispatched to a Rails controller action.
- `Shipit::Authentication` (`app/controllers/concerns/shipit/authentication.rb:7-8`) enforces `before_action :force_github_authentication`, but it is only ever `included` into `Shipit::ShipitController` (`app/controllers/shipit/shipit_controller.rb:18`). Since the mounted `Pubsubstub::StreamAction` never inherits from `ShipitController` (or any Rails controller at all — it's a raw Rack endpoint), this `before_action` never runs for `/events` requests.
- `lib/shipit/engine.rb` only wires optional `OmniAuth` and `SameSiteCookieMiddleware` into the middleware stack; neither performs authentication/authorization, and neither is placed in front of the mounted `StreamAction`.
- The API controllers' `authenticate_api_client` (`app/controllers/shipit/api/base_controller.rb:48`) is likewise irrelevant here since `/events` is not routed to `Api::BaseController`.

Because there is no engine-level Rack middleware, no route constraint, and no wrapping controller for the `/events` mount, an attacker's request `GET /events?channels=stack.1` (or any numeric/string channel name matching Pubsubstub's internal channel identifiers) reaches `Pubsubstub::StreamAction` directly and is serviced as a valid SSE stream, subscribing the connection to that channel's published events with zero authentication or authorization check performed by this engine's code.

### Impact Explanation
An attacker gains unauthenticated, live, repeatable read access to activity/reload signals for arbitrary stacks and repositories by guessing or enumerating small numeric/slug channel identifiers (e.g., `stack.1`, `stack.2`, ...). This is a cross-tenant information disclosure: any stack hosted on the Shipit instance — regardless of the requester's authorization to view it — leaks its push events (deploy/task/commit-status reload signals) to anyone on the internet who can reach the host. This matches the "unauthenticated read of stack state, task streams" High-severity category in the rules.

### Likelihood Explanation
- No preconditions beyond network reachability to the Shipit host; no secrets, tokens, GitHub team membership, or session are required.
- Channel names are derivable/enumerable (stack IDs are small sequential integers, repository names are `owner/repo` strings often public on GitHub).
- The request is a single unauthenticated `GET`, fully repeatable against every stack/repository ID on the instance.
- This holds under the documented default mounting in `config/routes.rb`, requiring no non-default host-app configuration.

### Recommendation
Wrap the `/events` mount with an authentication/authorization gate before it is reached — e.g., replace the direct engine-level `mount` with a controller action (or a small Rack middleware) that runs `Shipit::Authentication`-equivalent checks and validates that `current_user` (or `current_api_client`) is authorized to view the specific `stack_id`/`repository_id` encoded in the requested `channels` parameter before delegating to `Pubsubstub::StreamAction`. At minimum, constrain and validate the `channels` parameter against resources the caller has been granted access to, rejecting streams for any stack/repository the caller cannot otherwise `GET`.

### Proof of Concept
```ruby
# test/integration/unauthenticated_events_stream_test.rb
require 'test_helper'

class UnauthenticatedEventsStreamTest < ActionDispatch::IntegrationTest
  test "unauthenticated request to /events with a stack channel should be rejected" do
    stack = shipit_stacks(:shipit)

    # No cookies / session set — attacker holds no Shipit session or API token.
    get "/events", params: { channels: "stack.#{stack.id}" }

    # Binding under test: subscription to a stack channel should require the
    # requester to be authorized to view that stack (current_user.authorized?
    # for that stack), matching Shipit::Authentication#force_github_authentication.
    # Today this request is serviced by Pubsubstub::StreamAction with no
    # controller/auth in front of it, so it streams instead of being rejected.
    assert_response :unauthorized # or :forbidden / :redirect to github auth
  end
end
```
Running this against the current routing (`config/routes.rb:9`) demonstrates the SSE connection is accepted/streamed rather than rejected, confirming the missing authentication/authorization binding.