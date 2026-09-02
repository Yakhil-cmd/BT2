### Title
Unauthenticated SSE subscription to stack update channel via `/events` mount bypasses `force_github_authentication` - (File: config/routes.rb, app/models/shipit/stack.rb)

### Summary
`Pubsubstub::StreamAction` is mounted directly at `/events` in `config/routes.rb`, outside of any Shipit controller, so it never passes through `ShipitController`'s authentication filters. Any unauthenticated client can subscribe to `GET /events?stream=stack.<id>` and receive the same `update` events that `Stack#broadcast_update` normally only reaches authenticated users' browsers via the embedded `EventSource` in stack pages.

### Finding Description
The broken binding: `stack_page_view_requires(force_github_authentication) == stack_update_event_requires(force_github_authentication)`. Before: a user must pass `Shipit::Authentication#force_github_authentication` (included in `ShipitController`, `app/controllers/shipit/shipit_controller.rb:18`) to view `/*stack_id` and see live `update` events pushed by `PageUpdater` (`app/assets/javascripts/shipit/page_updater.js.coffee:43`, listening on the `subscription-channel` meta tag). After: `Pubsubstub::StreamAction.new` is `mount`ed at `/events` (`config/routes.rb:9`) as a separate Rack endpoint, never inheriting `ApplicationController`/`ShipitController` before_actions. `Stack#broadcast_update` (`app/models/shipit/stack.rb:561-567`) publishes `{ id:, updated_at: }.to_json` on channel `"stack.#{id}"` with no per-subscriber authorization check performed by `StreamAction` itself. Channel names are simple, guessable/enumerable identifiers (`stack.<id>`), and `Stack` ids are sequential, so an attacker can iterate `id` values with `GET /events?stream=stack.<id>` and receive `update` notifications (id + updated_at) for private/internal stacks without any session, token, or team membership — something otherwise gated by `force_github_authentication`.

Evidence found does **not** support the stronger claim that raw task/deploy command output (`Task#chunk_output`, potentially containing `GITHUB_TOKEN`-bearing command output) is broadcast over this same Pubsubstub channel. `Task#chunk_output`/`#tail_output` read from Redis (`app/models/shipit/task.rb:238-267`) and are served exclusively through authenticated HTTP endpoints (`tasks#tail`, `api/outputs#show`), not via `Pubsubstub.publish`. No `Pubsubstub.publish` call carrying raw task output was found in the indexed code; the only confirmed publisher is `Stack#broadcast_update`, which sends only `{id, updated_at}` metadata.

### Impact Explanation
An unauthenticated attacker gains a persistent, unauthenticated read of stack update events (stack id + last-updated timestamp) for any stack, including ones on private repositories, by guessing/enumerating sequential stack ids and subscribing at `/events?stream=stack.<id>`. This is repeatable against every stack in the instance with no rate limiting or per-tenant isolation, since the mount has zero authentication middleware. This matches the High severity category "unauthenticated read of stack state" — not the Critical "exfiltration of GITHUB_TOKEN" claim in the original report, because no evidence was found that task/deploy console output is transmitted through this channel.

### Likelihood Explanation
No preconditions beyond network access to the Shipit host and knowledge/guessing of a numeric stack id (trivially enumerable, e.g. `stack.1`, `stack.2`, ...). No secrets, sessions, or GitHub credentials are required, matching the unprivileged attacker model.

### Recommendation
Wrap `/events` with an authenticating/authorizing check before allowing subscription — e.g., implement a custom controller action (or `Rack::Builder` middleware chain) that validates the requester's session/API token and their authorization for the specific stack encoded in the `stream` param before delegating to `Pubsubstub::StreamAction`, instead of mounting it unauthenticated at the top level.

### Proof of Concept
```ruby
# test/integration/unauthenticated_events_stream_test.rb
require 'test_helper'

module Shipit
  class UnauthenticatedEventsStreamTest < ActionDispatch::IntegrationTest
    test "unauthenticated client can subscribe to a stack's update channel" do
      stack = shipit_stacks(:shipit)
      # no sign_in / session set

      get "/events", params: { stream: "stack.#{stack.id}" }, headers: { "Accept" => "text/event-stream" }

      assert_response :success
      # Compare: viewing the stack directly requires authentication
      get stack_path(stack)
      assert_response :redirect # force_github_authentication redirects unauthenticated users
    end
  end
end
```
This demonstrates the divergence: the stack page itself enforces `force_github_authentication`, but the equivalent live-update channel for the same stack does not.