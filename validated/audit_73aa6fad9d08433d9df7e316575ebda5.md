### Title
`repository.owner.login` vs `repository.full_name` org divergence lets a no-secret org's webhook forge a `pull_request reopened` event that unarchives another org's `ReviewStack` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) used to authenticate the webhook using `repository_owner`, which is read from `params.dig('repository','owner','login')`, while every `pull_request` handler (e.g. `ReopenedHandler`) resolves the target `Repository`/`Stack` using `params.repository.full_name`. These two values are never checked for consistency, so an attacker who controls both fields in an unsigned-looking payload can pick an org for signature verification that has no `webhook_secret` configured, while pointing `full_name` at a victim org's repository whose stack is mutated.

### Finding Description
The broken binding is: `repository_owner (used to select GitHubApp for verify_webhook_signature) == org(repository.full_name) (used by handler.repository to resolve the mutated Repository/Stack)`. This does not hold.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` (lines 24-30) calls `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(signature, raw_post)`, where `repository_owner` (line 59-62) reads only `params.dig('repository','owner','login')`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb, line 76-83) has `return true unless webhook_secret` — if the selected org's config has no `webhook_secret` set, **any** signature (or none) is accepted.
- `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler#repository` (app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb, lines 49-53) resolves the repository to mutate via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate field from `repository.owner.login`.

Because the controller never cross-checks that `repository.owner.login` equals the org embedded in `repository.full_name`, an attacker can craft a payload where `repository.owner.login = "attacker-org-with-no-secret"` and `repository.full_name = "victim-org/victim-repo"`. If `attacker-org-with-no-secret` is configured in `Shipit.github` (per `github_app_config`, lib/shipit.rb lines 196-200) without a `webhook_secret`, `verify_webhook_signature` short-circuits to `true` and the request passes `verify_signature` regardless of the actual `X-Hub-Signature` header. `Shipit::Webhooks.for_event('pull_request')` then dispatches to `ReopenedHandler.call(params)`, which resolves `repository` via `full_name` (victim org) and calls `stack.unarchive!` on the victim's `ReviewStack`, per `ReviewStackAdapter#unarchive!` (app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb, lines 37-50), potentially even creating a new stack via `create!` if none is archived-but-missing.

This matches the documented existing behavior/tests: `test/controllers/webhooks_controller_test.rb` line 109-127 shows that an *unknown* organization (not present in `Shipit.github` config at all) is rejected with 422 via `GithubOrganizationUnknown`. However, this guard only protects against organizations absent from configuration — it does nothing to prevent an attacker from choosing a *known but secret-less* organization for `repository.owner.login` while targeting an unrelated org's repository via `repository.full_name`. No code in `verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema (which only `requires :full_name, String`, never validates it against the owner), or the handler's `repository`/`stack` resolution methods enforces that these two fields agree.

Once inside the handler, `ignore_ci: true` on the victim stack means `Commit#deployable?` (app/models/shipit/commit.rb, line 227-229) returns `true` unconditionally (`!locked? && (stack.ignore_ci? || ...)`), so any subsequently pushed/pulled commit for the resurrected review stack is immediately shippable without passing CI, amplifying the impact of the forged unarchive.

### Impact Explanation
An attacker who owns or controls a GitHub org/repo configured in the target Shipit instance without a webhook secret can forge `pull_request` webhooks that are authenticated as if they came from that no-secret org, but whose `repository.full_name` field is used by the handler to select and mutate a completely different organization's `Repository`/`Stack`/`ReviewStack`. For the `reopened` action specifically, this causes `ReopenedHandler` to unarchive (or create) a `ReviewStack` belonging to a repository the attacker never proved control over. Combined with `ignore_ci: true` on the victim stack, `Commit#deployable?` treats any commit as shippable, so the resurrected/created review stack can proceed straight to deploy without CI gating — this is an unauthorized mutation of one repository's/org's stack state triggered by a payload that was authenticated for a different repository/org, matching "a payload for one repository mutating another's stack" (Critical).

### Likelihood Explanation
This requires: (1) the Shipit instance to be configured with the multi-org `Shipit.github(organization: ...)` schema (`github_default_organization` non-nil) and to have at least one org configured with an empty/absent `webhook_secret`; (2) a victim org/repository with `review_stacks_enabled` and a provisioning behavior that allows unarchiving (`allow_all`, or label-based conditions satisfiable by attacker-controlled PR labels); (3) `ignore_ci: true` on the victim stack to realize the "any commit is shippable" amplification. These are real, plausible operator misconfigurations (e.g., an internal low-risk org left without a secret for convenience) rather than exotic states, and the attacker only needs to send a single crafted unauthenticated HTTP POST to `/webhooks` — no session, token, or GitHub permission on the victim repo is required. The attack is fully repeatable against any repository resolvable via `Repository.from_github_repo_name`.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, after selecting `github_app` via `repository_owner`, additionally verify that the organization embedded in `params.dig('repository', 'full_name')` (the substring before `/`) matches `repository_owner` exactly, rejecting the request (422) on mismatch. Alternatively/additionally, require every configured org in `Shipit.github` to have a non-blank `webhook_secret` (fail closed rather than `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`), removing the "any signature passes" escape hatch entirely.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "pull_request reopened forged via secret-less org mutates a different org's stack" do
  # Precondition: configure an org "no-secret-org" in Shipit.github with webhook_secret blank,
  # and a distinct victim stack under "victim-org/victim-repo" with review_stacks_enabled,
  # provisioning_behavior allow_all, and ignore_ci: true, with an archived ReviewStack for PR #7.

  victim_repo = shipit_repositories(:victim) # full_name "victim-org/victim-repo"
  victim_stack = victim_repo.review_stacks.find_by(pull_request_id: ...) # archived

  payload = {
    action: "reopened",
    number: 7,
    pull_request: {
      id: 1, number: 7, url: "u", title: "t", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "attacker-branch" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: {
      full_name: "victim-org/victim-repo",   # <-- mutated org
      owner: { login: "no-secret-org" }      # <-- org used for signature verification
    },
    sender: { login: "attacker" }
  }.to_json

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid signature

  # Binding under test (should hold, but doesn't):
  # org(repository.owner.login) == org(repository.full_name.split('/').first)
  assert_not_equal "no-secret-org", "victim-org"

  assert_changes -> { victim_stack.reload.archived? }, from: true, to: false do
    post :create, body: payload, as: :json
  end
  assert_response :ok
end
```
This test demonstrates that a payload authenticated (trivially, due to `no-secret-org` having no `webhook_secret`) against `no-secret-org` is able to unarchive `victim-org/victim-repo`'s `ReviewStack`, violating the invariant that a `pull_request` event should only affect the repository/stack whose secret actually authenticated it.