### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the write target is resolved from the unverified `repository.full_name` field, allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body, then calls `Shipit.github(organization: repository_owner)` to fetch that organization's `GitHubApp` and verify the signature with its `webhook_secret`. Once the signature check passes, the actual handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) resolve the target repository/stack using a **different** field of the same unverified payload: `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "repository that gets written to" are never checked for equality.

### Finding Description
- `app/controllers/shipit/webhooks_controller.rb#verify_signature` (lines 24-30) computes:
  - `github_app = Shipit.github(organization: repository_owner)`
  - `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` (lines 59-62) — taken directly from the raw, unauthenticated POST body.
  - `github_app.verify_webhook_signature(signature, raw_post)` in `lib/shipit/github_app.rb#verify_webhook_signature` (lines 76-83) HMACs the raw body with that organization's own `webhook_secret` (from `Shipit.github_app_config(organization)`, `lib/shipit.rb#github_app_config`, lines 196-200) and compares it to `X-Hub-Signature`.
- `Shipit.github_organizations` / `Shipit.github_app_config` (`lib/shipit.rb`, lines 190-200) show that Shipit explicitly supports **multiple** GitHub App configurations keyed by organization, each with its own independent `webhook_secret`.
- Once `verify_signature` passes, `WebhooksController#create` dispatches: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (line 12), passing the entire raw JSON `params` unmodified.
- `Shipit::Webhooks::Handlers::Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb`, lines 36-38) reads `payload.dig('repository', 'full_name')` — a **separate JSON field from `repository.owner.login`** — and `#stacks` resolves `Repository.from_github_repo_name(repository_name)` to find the actual `Stack`s to act on (e.g. `PushHandler#process`, lines 12-17, calls `stack.sync_github`).
- Because the signature only proves "this body was signed with organization X's secret," and organization X is read from `repository.owner.login`, while the actual write target is `repository.full_name`, an attacker who is a legitimate GitHub App installer/administrator for **any** organization configured in Shipit (organization "X", e.g. their own org) can:
  1. Receive a real webhook delivery for organization X and thereby learn/derive a validly-signed payload structure, or otherwise obtain X's `webhook_secret` for the app they legitimately administer.
  2. Craft a payload where `repository.owner.login = "X"` (so signature verification looks up and passes against X's own secret) but `repository.full_name = "victim-org/victim-repo"`.
  3. Sign the raw body with X's own `webhook_secret` — a secret the attacker legitimately possesses because they administer their own GitHub App installation for organization X.
  4. POST this payload to `/webhooks`. `verify_signature` succeeds (X's secret validly signs the body). The dispatched handler (e.g. `PushHandler`) then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and triggers `stack.sync_github` on the **victim's** stack — an organization/repository the attacker never authenticated for.

This is the structural analogue of the `LongShort.sol` bug: the code verifies one field/index (`latestMarket` ≈ `repository.owner.login`) but then acts on a different field/index (`marketIndex` parameter ≈ `repository.full_name`) that was never covered by the check that was actually performed.

### Impact Explanation
This breaks the binding `{organization whose secret signed the request} == {repository/stack the handler writes to}`. In a multi-org Shipit deployment (which the engine explicitly supports via `Shipit.github_organizations`), an attacker with legitimate control over one configured GitHub App/organization can forge webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) that are attributed to and acted upon for a **different** organization's repositories/stacks that they have no access to. Depending on the handler this can trigger unauthorized `GithubSyncJob`s, spurious commit statuses, or membership/team changes for the victim organization — i.e., cross-organization/cross-repository writes performed without the victim's credentials, matching the "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires the deployment to be configured with more than one GitHub App/organization (`Shipit.github_organizations` with several entries), each with its own `webhook_secret`, and requires the attacker to legitimately administer at least one of those configured organizations/apps (so they know that organization's `webhook_secret`) while targeting another organization's stacks. This is a realistic misconfiguration/multi-tenant scenario the engine's own code explicitly supports (`github_app_config`), not a hypothetical one, and requires no privileged Shipit credentials, `ApiClient` token, or the victim's secret — only unprivileged control of one's own configured GitHub org, satisfying the "unprivileged attacker" requirement.

### Recommendation
After successfully verifying the signature, re-derive the organization from the same trusted source used for verification and cross-check it against the organization actually implied by `repository.full_name` (or `organization.login`) before dispatching to handlers — i.e., reject the webhook if `repository.full_name`'s owner does not match the `repository_owner` that was used to select the verifying `webhook_secret`. Alternatively, verify the signature using a lookup keyed off the resolved `Repository`/`Stack`'s actual configured organization rather than a value taken from the unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `attacker-org` (attacker administers the corresponding GitHub App/webhook) and `victim-org` (hosts `victim-org/victim-repo`, tracked by an existing Shipit `Stack`).
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` — a secret the attacker legitimately possesses.
4. POST the body to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner == "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature check passes since it was signed with that org's real secret.
6. `Shipit::Webhooks::Handlers::PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — a write the attacker never had credentials for.