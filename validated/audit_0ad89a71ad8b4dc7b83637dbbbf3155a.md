### Title
Deploy/task actor attribution forged via unauthenticated `X-Shipit-User` header - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Shipit::Api::BaseController#identify_user` derives `current_user` purely from the client-supplied `X-Shipit-User` request header, with no cryptographic or ownership check tying it to the authenticated `ApiClient` token. Any caller holding a valid API token for any permitted scope can set this header to an arbitrary existing user's login and have that user recorded as the actor on created `Task`/`Deploy` records.

### Finding Description
The broken binding: `current_user` (used as the deploy/task actor) should equal `current_api_client.creator` (the identity that authenticated the request via Basic Auth token), but instead `current_user == User.where('lower(login) = ?', request.headers['X-Shipit-User'].downcase).first`, an entirely attacker-controlled value.

Code path: `authenticate_api_client` (app/controllers/shipit/api/base_controller.rb:48-61) validates the Basic Auth token against `ApiClient.authenticate`, setting `@current_api_client`. `require_permission!` (line 82-84) only calls `current_api_client.check_permissions!(operation, scope)`, which checks that the token's `permissions` array includes e.g. `deploy:stack` (app/models/shipit/api_client.rb:38-45) — it never touches `current_user`. Separately, `current_user` (lines 65-67) lazily calls `identify_user` (lines 69-72), which reads `request.headers['X-Shipit-User']` directly and looks up a `User` by lowercased login with no relation whatsoever to `current_api_client`. This resolved `current_user` is what controllers (e.g. deploys/rollback controllers) pass in as the task/deploy creator.

Attacker request: possess any valid `ApiClient` token that has been granted `deploy:stack` for their own stack (a legitimately obtained, low-privilege token scoped only to that stack), then `POST /api/stacks/:id/deploys` with `X-Shipit-User: <victim-login>` in the headers. `authenticate_api_client` accepts the token (it's valid), `require_permission!` passes (the token does have `deploy:stack` for that stack_id), and `identify_user` resolves `current_user` to the victim's `User` record purely from the header — no verification that the header value matches `current_api_client.creator` or any authenticated identity.

Existing guards do not prevent this: `check_permissions!` only validates operation/scope strings against the token's `permissions` array; it has no concept of the acting user. There is no code anywhere in `base_controller.rb` (or subclasses) that cross-checks the `X-Shipit-User` header against `current_api_client.creator` or any session/OAuth-derived identity.

### Impact Explanation
Any deploy, rollback, or other task-creating action performed via the API with a spoofed header results in a `Task`/`Deploy` row whose recorded actor/creator is an arbitrary Shipit user chosen by the attacker, rather than the true token holder. This corrupts audit trails and attribution data, and can feed downstream logic that trusts `current_user` for notification, approval, or "who deployed this" display purposes — misattributing unauthorized/malicious deploys to innocent users. This is repeatable on every API request the attacker's token is permitted to make (bounded to whatever stack/scope the token's permissions actually cover), and constitutes identity spoofing/forged attribution matching the Critical category ("unauthorized deploy... attribution").

### Likelihood Explanation
Preconditions are modest: the attacker needs any legitimately issued `ApiClient` token with at least one permission relevant to the action they want to perform (e.g. `deploy:stack` for their own stack) — this requires no secrets, no GitHub App keys, and no privileged role beyond having been issued an API token via `Shipit::ApiClientsController` (a normal, low-friction flow for stack contributors). Setting an arbitrary header on an HTTP request is trivial and requires no special access. The attack is fully repeatable for every request the token is authorized to issue.

### Recommendation
Remove trust in the client-supplied `X-Shipit-User` header for attribution. Instead, derive `current_user` from `current_api_client.creator`, or require that impersonation via `X-Shipit-User` only be honored for a special class of trusted/service tokens (e.g., an explicit `impersonate` permission), validating that the requested login is authorized to be impersonated by that specific token before resolving `current_user`.

### Proof of Concept
In `test/controllers/api/deploys_controller_test.rb` style:
1. Create `victim = shipit_users(:walrus)` (or similar fixture) and `attacker_client = shipit_api_clients(:some_client)` with only `deploy:stack` permission scoped to a stack the attacker owns, with `creator` set to a different, low-privilege attacker user.
2. `post api_deploys_url(stack_id: stack.to_param), headers: { 'Authorization' => "Basic #{Base64.encode64(attacker_client.authentication_token + '--')}", 'X-Shipit-User' => victim.login }, params: {...valid deploy params...}`
3. Assert response success (permission check passes).
4. Assert `Task.last.user_id == victim.id` (or `Deploy.last.creator == victim`) — i.e., the created task's actor equals the spoofed victim rather than `attacker_client.creator`, demonstrating `current_user != current_api_client.creator` despite no authentication of the `X-Shipit-User` value.