## Title
Multi-tenant Shipit deployments accept forged `pull_request` webhooks for any org with `webhook_secret` unset, allowing cross-org record forgery via `AssignedHandler` - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb)

## Summary
`WebhooksController#repository_owner` selects the verifying `GitHubApp` from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `AssignedHandler#repository` independently derives the target repository from `params.repository.full_name`. Because these two selectors read different, independently attacker-controlled JSON fields, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, an attacker who knows of any configured org without a `webhook_secret` can pass signature verification while pointing `repository.full_name` at a stack belonging to a different (secured) org.

## Finding Description
The broken invariant, stated as an equality that should hold but doesn't:

`organization_that_authenticated_request == organization_owning(params.repository.full_name)`

Trace:
- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) picks the verifier via `repository_owner`, defined as `params.dig('repository','owner','login') || params.dig('organization','login')` (line 61).
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) does `return true unless webhook_secret` — any org configured with `webhook_secret` blank/nil (as in `test/dummy/config/secrets_double_github_app.yml`, both `OrgOne` and `OrgTwo` have `webhook_secret:` empty) accepts **any** signature unconditionally.
- `AssignedHandler`'s `ExplicitParameters` schema only `requires :repository { requires :full_name, String }` — it does not require `repository.owner` (app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb:33-35). The handler resolves the target repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (line 68), completely independent of whatever value was used by `repository_owner` for signature selection.
- An attacker can therefore submit a JSON body containing `"organization": {"login": "OrgOne"}` (a known org with no `webhook_secret`) together with `"repository": {"full_name": "victim-org/victim-repo"}` (omitting `repository.owner` entirely, or setting it to anything, since it's not required by the schema). `verify_signature` calls `Shipit.github(organization: "OrgOne")`, gets a `GitHubApp` with `webhook_secret` nil, and `verify_webhook_signature` returns `true` regardless of the (even absent/garbage) `X-Hub-Signature` header.
- The request then proceeds to `Shipit::Webhooks.for_event('pull_request').each { |handler| handler.call(params) }` (app/controllers/shipit/webhooks_controller.rb:12), invoking `AssignedHandler#process`, which calls `pull_request.update(github_pull_request: params.pull_request)` (assigned_handler.rb:44) for the actual `PullRequest` record tied to `victim-org/victim-repo`'s stack — a repository that never authenticated this request.

None of the existing guards catch this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` validates payload shape, not org/repo consistency; there is no check anywhere that the org used for signature verification matches the org that owns `params.repository.full_name`.

## Impact Explanation
An attacker can mutate the persisted `Shipit::PullRequest` record (`github_pull_request` JSON blob) for any repository/stack configured in the target Shipit instance, as long as (a) they know of at least one org configured in `Shipit.secrets.github` without a `webhook_secret`, and (b) the target `number`/repository combination has an existing `PullRequest` row. This is a payload for one (no-secret) org's webhook forging state for another org's stack — matching the "payload for one repository mutating another's stack" Critical impact category. The attack is fully repeatable against any stack/PR pair and requires no session, no API token, and no knowledge of any actual webhook secret.

## Likelihood Explanation
Preconditions: the Shipit instance must be a multi-org deployment (`secrets.github` keyed by multiple organizations) where at least one configured org has no `webhook_secret` set — a legitimate, documented configuration state (see `test/dummy/config/secrets_double_github_app.yml`). Attacker cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted JSON body; no secrets, sessions, or privileged roles required. This is feasible and fully repeatable.

## Recommendation
Enforce that the organization used to select/verify the webhook signature matches the organization that owns the repository referenced by the payload's actual event data. Concretely: derive `repository_owner` exclusively from `params.dig('repository','owner','login')` (do not fall back to `organization.login` when a `repository` field with a different owner is present), and/or have each handler independently re-validate that `params.repository.full_name`'s owner equals the `repository_owner` used for verification before processing. Additionally, `AssignedHandler`'s schema should require and validate `repository.owner.login` and cross-check it against the verified organization.

## Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "pull_request assigned event with mismatched organization vs repository.full_name updates victim stack's PullRequest" do
  # Setup: two orgs in secrets.github — "OrgOne" (no webhook_secret) and "OrgTwo" (has webhook_secret)
  # victim_repo belongs to "OrgTwo" org's stack, has an existing PullRequest with number: 42

  victim_repo = shipit_repositories(:shipit) # owned by OrgTwo per secrets
  stack = victim_repo.stacks.first
  pr = create_pull_request(stack: stack, number: 42, github_pull_request: { "state" => "open" })

  payload = {
    action: "assigned",
    number: 42,
    organization: { login: "OrgOne" },  # org with no webhook_secret -> verify_webhook_signature returns true unconditionally
    repository: { full_name: victim_repo.full_name }, # targets victim stack, no `owner` key required by schema
    pull_request: {
      id: 1, number: 42, url: "http://example.com", title: "t", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "master" },
      user: { login: "attacker" },
      assignees: [{ login: "attacker" }],
      labels: []
    },
    sender: { login: "attacker" }
  }.to_json

  post "/webhooks", params: payload, headers: {
    "Content-Type" => "application/json",
    "X-Github-Event" => "pull_request",
    "X-Hub-Signature" => "sha1=garbage" # arbitrary/invalid, irrelevant since OrgOne has no secret
  }

  assert_response :ok
  pr.reload
  # Assertion: PR belonging to OrgTwo's stack was mutated by a request "authenticated" against OrgOne
  assert_equal ["attacker"], pr.github_pull_request["assignees"].map { |a| a["login"] }
end
```

Both sides of the binding before the fix: `repository_owner` resolves to `"OrgOne"` while the actually-affected repository (`victim_repo.full_name`) belongs to `"OrgTwo"` — they diverge, and the handler still executes and persists the write, confirming the vulnerability.