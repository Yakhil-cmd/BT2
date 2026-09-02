### Title
Webhook signature verification is keyed off `repository.owner.login`, but event handlers act on `repository.full_name` — a per-organization webhook secret bypass lets an attacker forge events for any repository whose owning organization has `webhook_secret` unset - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the inbound payload's `X-Hub-Signature` against, based solely on `repository_owner`, itself derived from the untrusted, unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). <cite repo="Jaredbentat/shipit-engine--009" path="app/controllers/shipit/webhooks_controller.rb" start="24-30" end="59-62" /> Once verification passes, the handlers that actually act on the payload (e.g. `PushHandler`, and the shared `Handlers::Handler#stacks`) resolve the target `Repository`/`Stack` from a *different* field in the same payload: `payload.dig('repository', 'full_name')`. <cite repo="Jaredbentat/shipit-engine--009" path="app/models/shipit/webhooks/handlers/handler.rb" start="32-38" end="32-38" /> These two fields are never checked for consistency, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` whenever the selected organization's `webhook_secret` happens to be blank: `return true unless webhook_secret`. <cite repo="Jaredbentat/shipit-engine--009" path="lib/shipit/github_app.rb" start="76-83" end="76-83" />

### Finding Description
`Shipit.github(organization:)` looks up per-organization GitHub App configuration by the organization key present in `secrets.github`, keyed off whatever the caller asked for. <cite repo="Jaredbentat/shipit-engine--009" path="lib/shipit.rb" start="170-181" end="196-200" /> The webhooks controller passes the organization derived purely from the request body:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
<cite repo="Jaredbentat/shipit-engine--009" path="app/controllers/shipit/webhooks_controller.rb" start="24-62" end="24-62" />

If the deployment hosts multiple GitHub organizations (as documented in `docs/setup.md`, and as tested in `test/dummy/config/secrets_double_github_app.yml`), each organization may have its own `webhook_secret`; the fixture even shows one org configured with `webhook_secret: # nil`. <cite repo="Jaredbentat/shipit-engine--009" path="test/dummy/config/secrets_double_github_app.yml" start="41-46" end="41-46" /> `GitHubApp#verify_webhook_signature` treats a blank secret as "verification not required":

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
<cite repo="Jaredbentat/shipit-engine--009" path="lib/shipit/github_app.rb" start="76-83" end="76-83" />

Because `repository_owner` is read from the unauthenticated payload before any signature is checked, an attacker can craft a POST to `/webhooks` claiming `repository.owner.login` = the org with no `webhook_secret`, while setting `repository.full_name` to a *different* repository (belonging to any organization actually configured in this Shipit instance). The signature check will pass unconditionally (or with a signature the attacker computes trivially, since no secret is enforced), and the handler that processes the event resolves the real target repository/stack purely via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, with no cross-check that `full_name`'s owner matches `repository_owner`. <cite repo="Jaredbentat/shipit-engine--009" path="app/models/shipit/webhooks/handlers/handler.rb" start="32-38" end="32-38" /> <cite repo="Jaredbentat/shipit-engine--009" path="app/models/shipit/repository.rb" start="53-56" end="53-56" />

This is the exact analog of the `L1Escrow.approve()` bug class: the "authorized" entity (`DEFAULT_ADMIN_ROLE`/here, "the organization whose secret was checked") is decoupled from the entity actually acted upon (`_spender`/here, "the repository whose stack receives the forged webhook event"). The binding that should hold — `organization verified by signature == organization owning the repository being written to` — is broken: an attacker fully controls both sides of that equation via unauthenticated payload fields, and only one side is checked.

### Impact Explanation
A successfully forged event lets an unauthenticated attacker trigger `GithubSyncJob`, membership/team mutations (`Membership`/`Team` creation, as seen in `test/controllers/webhooks_controller_test.rb`'s `:membership` tests), pull request state changes, and check-run/status driven merge-queue transitions for *any* repository/stack configured in the Shipit instance — not limited to the mis-configured organization. Depending on which handlers are registered, this can lead to an unauthorized merge or an unauthorized deploy trigger path (`push` → `GithubSyncJob` → deploy pipeline), satisfying the "unauthorized deploy, rollback or merge" Critical-impact bar, provided the multi-org config includes at least one organization without `webhook_secret` set.

### Likelihood Explanation
Exploitability is entirely conditioned on the operator's own multi-tenant configuration containing at least one organization entry with a blank/missing `webhook_secret` — the codebase supports and documents this (`docs/setup.md` marks `webhook_secret` as optional, and the fixture `secrets_double_github_app.yml` demonstrates a real org configured with `webhook_secret: # nil`). Given that configuration, the attack requires no credentials, no session, and no GitHub App key — only knowledge of the target Shipit host's `/webhooks` URL and the names of the (misconfigured) org and the real target repository, both of which are typically public information (organization/repo names visible on GitHub). This is a genuine unauthenticated-attacker path once the described (supported, non-default) configuration exists.

### Recommendation
- After resolving `repository_owner`, cross-validate that `payload.dig('repository','full_name')` (and `organization.login`, if present) actually belongs to the same organization used to select the `GitHubApp`/secret, rejecting mismatches.
- Do not treat a blank `webhook_secret` as "skip verification" for multi-organization configurations; require every configured organization to set a webhook secret, or refuse to boot/verify_signature must fail closed when `github_default_organization` indicates a multi-org setup.
- Alternatively, verify the signature against every configured organization's secret and require the resulting authenticated organization to equal the organization owning the repository referenced in the payload before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `OrgA` (no `webhook_secret`) and `OrgB` (real secret, real stacks) — mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "after": "<attacker-chosen sha>",
  "ref": "refs/heads/main"
}
```
   Any `X-Hub-Signature` value (or none) is accepted because `GitHubApp#verify_webhook_signature` returns `true` for `OrgA`'s blank secret. <cite repo="Jaredbentat/shipit-engine--009" path="lib/shipit/github_app.rb" start="76-83" end="76-83" />
3. `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event('push')`, whose handler resolves the stack via `Repository.from_github_repo_name('OrgB/target-repo')` and enqueues `GithubSyncJob` for `OrgB`'s real stack — despite the request never being signed by `OrgB`'s secret. <cite repo="Jaredbentat/shipit-engine--009" path="app/models/shipit/webhooks/handlers/handler.rb" start="32-38" end="32-38" />