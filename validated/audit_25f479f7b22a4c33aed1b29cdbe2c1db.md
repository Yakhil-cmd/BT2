### Title
CCMenu API token minted with no stack scope grants read access to every stack's CI status - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#client` mints an `ApiClient` with `permissions: %w[read:stack]` but never sets `stack:`, leaving `stack_id` nil, and `Shipit::Api::CCMenuController` authenticates purely via `ApiClient.authenticate(params[:token])` and resolves the stack with `Stack.from_param!(params[:stack_id])` directly rather than through the stack-scoped `stacks` helper used elsewhere in `Api::BaseController`. The binding "token minted for stack A only authorizes reads of stack A" (`current_api_client.stack_id == requested stack.id`) never holds: it is neither established at mint time nor enforced at use time.

### Finding Description
Broken binding: `client.stack_id` should equal `stack.id` for the stack the CCMenu URL was generated for, but `CCMenuUrlController#client` (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`) calls `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` with no `stack:` attribute, so `client.stack_id` is always `nil`.

At use time, `Shipit::Api::CCMenuController` (`app/controllers/shipit/api/ccmenu_controller.rb:29-36`) overrides `authenticate_api_client` to call `ApiClient.authenticate(params[:token])` (matching solely on the signed client id via `Shipit::SimpleMessageVerifier`, see `app/models/shipit/api_client.rb:24-27`), and overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly — it does **not** call the `stacks` method defined in `Api::BaseController` (`app/controllers/shipit/api/base_controller.rb:74-76`), which is the only place `current_api_client.stack_id` is ever consulted to restrict a query (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`). `require_permission :read, :stack` only checks that `'read:stack'` is present in `permissions` (`ApiClient#check_permissions!`), not that the client's `stack_id` matches the requested stack.

Consequently, even a correctly-scoped `ApiClient` (with `stack_id` set) would still bypass the restriction in `CCMenuController`, and the CCMenu client (which is unscoped by construction) trivially works against any stack.

Exploit flow: an authenticated, `Shipit.github_teams`-authorized user visits `GET /*stack_id/ccmenu_url` for stack A (a stack they legitimately have UI access to), receiving `client.authentication_token`. They replay `GET /api/stacks/*stackB/ccmenu?token=...` for an unrelated stack B and successfully retrieve stack B's build/deploy status.

Important caveat found during tracing: `Shipit::User#authorized?` (`app/models/shipit/user.rb:80-82`) and `force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) grant access based solely on global `Shipit.github_teams` membership — there is no per-stack ACL anywhere in `StacksController`/`ShipitController`. Any authorized Shipit user can already view any stack's HTML page (`StacksController#show`, no stack-level authorization check) and thus already sees the same build/deploy status information that CCMenu exposes. This means the "attacker with access to only stack A" precondition described in the prompt does not correspond to an actual access restriction in this codebase: Shipit's web UI has no concept of restricting a logged-in, team-authorized user to a subset of stacks. The bug is real (the token is unscoped and CCMenuController doesn't check scope), but its practical impact is limited to exposing CI/build-status XML that an authorized Shipit user could already view via the normal web UI for any stack — it does not cross a genuine tenant/authorization boundary given how this engine's access model works.

### Impact Explanation
Any `ApiClient` minted via CCMenuUrlController (and, independently, any `ApiClient` used against `CCMenuController`) can read `read:stack`-level data (deploy/build status, `name`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for **any** stack, not just the one it was minted for, because `CCMenuController#stack` bypasses the `stacks` scoping helper entirely. This is a real authorization-scoping bug, but since Shipit's own authorization model (`User#authorized?`) is global (team-membership based) rather than per-stack, an attacker capable of reaching `/ccmenu_url` is already an "authorized" user with equivalent web-UI visibility into all stacks. No secrets, deploy actions, commits, or write operations are exposed or affected; only read-only CI status data, which the same user could already view.

### Likelihood Explanation
Trivial to trigger: requires only an existing authenticated, `Shipit.github_teams`-authorized session (no privileged role), one GET to `/ccmenu_url` for any stack, and one GET to `/api/stacks/:other/cc_menu.xml?token=...`. No GitHub secrets, `api_clients_secret`, or admin access needed.

### Recommendation
- Set `stack: stack` when creating the `ApiClient` in `CCMenuUrlController#client` (`app/controllers/shipit/ccmenu_url_controller.rb:16-17`).
- Fix `Shipit::Api::CCMenuController#stack` to resolve the stack through the scoped `stacks` method (as `Api::BaseController` does) instead of `Stack.from_param!(params[:stack_id])` directly, so `current_api_client.stack_id` is actually enforced.

### Proof of Concept
```ruby
# test/controllers/ccmenu_url_controller_test.rb (existing file) - add:
test "minted client is not scoped to a stack" do
  get :fetch, params: { stack_id: @stack.to_param }
  client = ApiClient.last
  assert_nil client.stack_id # currently passes - demonstrates unscoped token
end

# test/controllers/api/ccmenu_controller_test.rb - add:
test "a CCMenu token minted for stack A authenticates against stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client', permissions: %w[read:stack])
  # client.stack_id is nil, mimicking CCMenuUrlController#client
  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }
  assert_response :ok # currently succeeds for an unrelated stack - demonstrates missing scope enforcement
end
```
Both assertions confirm `current_api_client.stack_id` never equals (or restricts to) `stack.id`, contradicting the intended binding — though note (per Finding Description) this does not cross an actual privilege boundary given Shipit's global, non-per-stack authorization model.