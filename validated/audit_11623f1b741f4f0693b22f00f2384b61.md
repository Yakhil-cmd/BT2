### Title
Cross-organization webhook forgery: signature verified against `repository.owner.login`/`organization.login` but events are dispatched by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App Shipit deployment, `WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the request signature against using `repository_owner`, which reads `repository.owner.login` (or `organization.login`) from the **same, unauthenticated** JSON body. Every webhook `Handler` (e.g. `PushHandler`), however, resolves the actual target repository/stack using a **different** field from that same body: `repository.full_name` via `Handler#repository_name`. Because these two fields are never cross-checked against each other, an attacker who controls one GitHub organization configured in Shipit (with a webhook secret they know) can forge a signature that is valid for "their" organization while making `repository.full_name` point at a victim organization's repository, causing Shipit to act on the victim stack.

### Finding Description
The binding that should hold is: `organization used to select/verify the signing secret == organization that owns the repository the payload actually targets`. This engine breaks that equality:

- `verify_signature` picks the `GitHubApp`/secret via `repository_owner`, taken from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`:
<cite repo="hirayap/shipit-engine--008" path="app/controllers/shipit/webhooks_controller.rb" start="24,59" end="30,62" />

- The dispatched handlers instead resolve the target repository from `repository.full_name`:
<cite repo="hirayap/shipit-engine--008" path="app/models/shipit/webhooks/handlers/handler.rb" start="32,36" end="34,38" />

- `Shipit.github(organization:)` looks up per-organization config by that org name, and `verify_webhook_signature` returns `true` unconditionally if that organization has no `webhook_secret` configured:
<cite repo="hirayap/shipit-engine--008" path="lib/shipit.rb" start="170,181" end="180,181" />
<cite repo="hirayap/shipit-engine--008" path="lib/shipit/github_app.rb" start="76,83" end="76,83" />

Attack: In a deployment using "Using Multiple GitHub Applications" (documented in `docs/setup.md`), suppose Shipit is configured for organizations `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret`. The attacker administers `attacker-org` and therefore knows its `webhook_secret` (or it may be left blank, per the `webhook_secret: # nil` pattern shown in `test/dummy/config/secrets.yml` and `config/secrets.development.shopify.yml`, which trivially bypasses verification for that org entirely). The attacker then POSTs a forged `push` webhook to `/webhooks` where:
- `repository.owner.login` = `attacker-org` (used only to pick the verification key)
- `repository.full_name` = `victim-org/victim-repo` (used to find the actual `Stack`)
- `ref` / `after` = attacker-chosen values

`verify_signature` computes the HMAC using `attacker-org`'s secret (which the attacker legitimately possesses or which is blank), so the check passes. `PushHandler#process` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on stacks the attacker has no ability to push to:
<cite repo="hirayap/shipit-engine--008" path="app/models/shipit/webhooks/handlers/push_handler.rb" start="12,17" end="16,17" />

This is a confused-deputy pattern directly analogous to the reported exploit's bug class: a field that is checked/verified (here, the organization/secret-selection field) is not the same field that the business logic subsequently acts on (here, the target-repository field), even though both are attacker-supplied in the identical unsigned-before-verification JSON body.

### Impact Explanation
This breaks the "an organization that authenticated versus the repository that is written" trust binding explicitly called out as in-scope. It allows an attacker who controls (or merely knows a config detail of) one org registered with Shipit to inject forged webhook events—forged `expected_head_sha` values, statuses, check-suite results, pull-request events, etc.—against stacks belonging to a completely unrelated organization/repository, without possessing that organization's GitHub App credentials or webhook secret. Depending on which webhook handler is targeted (`push`, `status`, `check_suite`, `pull_request`), this can influence sync/deploy state on the victim's stack, meeting the "cross-repository writes" / "unauthorized deploy" bar.

### Likelihood Explanation
Exploitability depends on the Shipit instance being configured with multiple GitHub organizations (a documented, supported configuration) and the attacker having legitimate control (as an org admin) or knowledge of one of those orgs' webhook secret — or that org having no secret configured at all, which the code explicitly tolerates (`return true unless webhook_secret`). No `ApiClient` token, GitHub App private key, or Shipit session is needed; the only requirement is administration of one registered-but-low-trust GitHub organization, which is a materially weaker privilege than the ones this scan excludes (repository write access to the victim repo, GITHUB_TOKEN, etc.).

### Recommendation
When verifying webhook signatures, require that the same repository/organization identity used to select the verification key is the one subsequently acted upon by the handler — e.g., after signature verification succeeds, re-derive `repository.full_name`'s owner and assert it matches `repository_owner`/`organization.login` before dispatching to `Shipit::Webhooks.for_event`. Alternatively, refuse to accept a blank `webhook_secret` for any organization once multi-organization mode is enabled, and reject events where `repository.owner.login` does not match the derived owner segment of `repository.full_name`.

### Proof of Concept
Given Shipit configured with two orgs `attacker-org` (attacker-controlled GitHub App, known/blank webhook secret) and `victim-org` (existing stack, e.g. `victim-org/victim-repo`):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC of body using attacker-org's webhook_secret>
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
`verify_signature` (app/controllers/shipit/webhooks_controller.rb) selects `Shipit.github(organization: "attacker-org")` and validates successfully using the attacker's own secret; `PushHandler` (app/models/shipit/webhooks/handlers/push_handler.rb + handler.rb) then looks up and acts on `victim-org/victim-repo`'s stack using the attacker-supplied `after` SHA.

**Note on verification confidence:** I was unable to execute this in a running instance; the analysis is based on static code review of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`/`push_handler.rb`, and `lib/shipit.rb`/`lib/shipit/github_app.rb`. I could not fully confirm whether any additional handler-level check (outside the reviewed files) re-validates the organization/repository owner consistency before acting; a full audit of all handlers under `app/models/shipit/webhooks/handlers/**` (e.g. `pull_request/*`) would be needed to confirm the same gap applies uniformly.