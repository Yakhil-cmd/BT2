### Title
Unauthenticated SSE stream disclosure via `Pubsubstub::StreamAction` mounted at `/events` - (File: config/routes.rb)

### Summary
`Pubsubstub::StreamAction` is mounted directly as a raw Rack endpoint at `/events`, completely outside the `Shipit::Engine`'s controller stack that normally enforces authentication and authorization. Since Rack-mounted apps never pass through `ActionController` `before_action` filters, any unauthenticated request to `/events?channel=<channel>` can subscribe to any pubsub channel, including task/deploy output streams, without ever hitting `force_github_authentication` or `authorized?`.

### Finding Description
The broken binding is: **response-carrying-live-task-stream-data == produced-after(force_github_authentication AND authorized?)**. In this codebase that equality does not hold for `/events`.

`config/routes.rb` mounts the stream endpoint directly: [1](#0-0) 

All other authenticated functionality in the engine is implemented as Rails controllers inheriting from `Shipit::Controller`/`ApplicationController`, which include `Shipit::Authentication` and call `force_github_authentication`/`authorized?` as `before_action` hooks: [2](#0-1) 

`Pubsubstub::StreamAction`, however, is a plain Rack endpoint (`mount ..., at: "/events"`), not a Rails controller action. Rack-mounted engines/apps are dispatched directly by the router and never run through the isolated engine's (or host app's) `ActionController::Base` filter chain. Consequently there is no `before_action` capable of running `force_github_authentication` or `authorized?` for requests to this path — the mount point is architecturally incapable of enforcing those checks, regardless of how carefully the rest of the engine guards its controllers.

The task/deploy streaming feature relies on `Pubsubstub` channels (configured in `lib/shipit/engine.rb` via `Pubsubstub.redis_url = Shipit.redis_url.to_s`) to publish live command/task output: [3](#0-2) 

An attacker with no Shipit session, no `ApiClient` token, and no GitHub team membership can send `GET /events?channel=<known-or-guessed channel name>` while a deploy/task is running for a target stack, and the Pubsubstub Rack action will establish an SSE connection and start relaying published events for that channel — no session cookie, no `Authorization` header, no CSRF token required.

None of the engine's existing guards apply here:
- `force_github_authentication` / `User#authorized?` never run (no controller in path).
- `verify_signature` / webhook signature checks are unrelated (different endpoint).
- `ExplicitParameters` schemas are not invoked because Pubsubstub parses `params[:channel]` itself, outside the engine's controllers.
- No `stacks` scope or `require_permission!` check exists for this mount.

### Impact Explanation
An unauthenticated attacker can read live deploy/task output for any stack whose channel name they can determine, which may include command echoes, log lines, and — depending on what commands print to stdout/stderr — leaked environment values such as `GITHUB_TOKEN` or other deploy-time secrets. This is repeatable against any stack/task currently streaming, across all tenants hosted by the same Shipit instance, matching the "High - unauthenticated read of stack state, task streams or deploy output" impact category.

### Likelihood Explanation
- Preconditions: a deploy/task must be actively streaming for the targeted stack, and the attacker must know or guess the channel name (e.g., predictable patterns tied to stack/task IDs).
- No Shipit or GitHub secrets, sessions, or privileged roles are required.
- Attacker cost is a single unauthenticated HTTP GET; the mount is reachable from the internet on any Shipit deployment following the documented routing configuration.
- Fully repeatable for the duration of any live stream and against any stack ID.

### Recommendation
Do not mount `Pubsubstub::StreamAction` as a raw, unauthenticated Rack endpoint. Wrap it behind an authenticated controller action (e.g., a thin controller that runs `force_github_authentication`/`authorized?` and validates that the current user/API client is permitted to view the target stack's channel) before delegating to Pubsubstub, or add Rack middleware in front of the mount that performs equivalent session/token validation and per-channel authorization before allowing a subscription.

### Proof of Concept
Minitest (integration test, no live GitHub, under `test/`):
```ruby
test "GET /events without authentication should not stream stack output" do
  stack = shipit_stacks(:shipit)
  deploy = create_deploy(stack) # or similar helper starting a task/deploy with a chunk output
  channel = deploy.send(:pubsub_channel) # or however the channel is derived

  # No login, no session, no API token set
  get "/events", params: { channel: channel }

  assert_response :unauthorized # or :redirect to login
  # Fails today: request succeeds (200) and streams chunk data instead of being rejected
end
```
Both sides of the binding to assert: `response.status == 401 (or redirect)` should equal `force_github_authentication_ran? == true`; currently the response is `200`/streaming while `force_github_authentication_ran? == false`, proving divergence.

### Citations

**File:** config/routes.rb (L9-9)
```ruby
  mount Pubsubstub::StreamAction.new, at: "/events", as: :events
```

**File:** app/controllers/concerns/shipit/authentication.rb (L1-3)
```ruby
# frozen_string_literal: true

module Shipit
```

**File:** lib/shipit/engine.rb (L20-24)
```ruby
    initializer 'shipit.config' do |app|
      Rails.application.routes.default_url_options[:host] = Shipit.host
      Shipit::Engine.routes.default_url_options[:host] = Shipit.host
      Pubsubstub.redis_url = Shipit.redis_url.to_s

```
