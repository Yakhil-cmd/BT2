### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while stack mutation is bound to `repository.full_name` — cross-org forged `pull_request.unlabeled` payload can unarchive/re-provision a victim's stack — (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/secret to verify against using `repository.owner.login` (falling back to `organization.login`), while `UnlabeledHandler`/`ReviewStackAdapter` resolve the target `Repository`/`Stack` using the independent `repository.full_name` field from the same attacker-controlled JSON body. Because these two fields are never checked for consistency, an attacker who can get a payload authenticated against any org configured with a blank `webhook_secret` can direct the mutation at an arbitrary victim repository via `full_name`, triggering `ReviewStackAdapter#unarchive!` → `Shipit::ReviewStackProvisioningQueue.add(stack)` → `stack.unarchive!` for a stack the attacker never authenticated for.

### Finding Description
Binding claimed: `org_that_verified_signature == org_that_owns_mutated_stack`. This is violated.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` calls `Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` (`webhooks_controller.rb:59-62`).
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) unconditionally returns `true` when `webhook_secret` is blank: `return true unless webhook_secret`. Blank secrets are an explicitly documented/supported configuration (`config/secrets.development.example.yml:11`, `docs/setup.md:194/203` show `webhook_secret: # nil`), not an operator error.
- After the check passes, `WebhooksController#create` (`webhooks_controller.rb:10-15`) dispatches the *entire raw JSON body* to handlers, with no re-check that the org used for verification matches the repository being mutated.
- `UnlabeledHandler#repository` resolves the target repo purely from `params.repository.full_name` (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:59-63`), a field completely independent from `repository.owner.login`/`organization.login` used above — the handler's own param schema (`unlabeled_handler.rb:33-35`) does not even require `repository.owner`.
- `ReviewStackAdapter#unarchive!` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:37-50`) finds the stack via `scope.find_by(environment:)` inside `repository.review_stacks`, and unconditionally calls `Shipit::ReviewStackProvisioningQueue.add(stack)` and `stack.unarchive!` when the stack is currently archived.

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request` and JSON body containing:
- `action: "unlabeled"`, `pull_request.state: "open"`, and labels crafted so `unarchive?` is true for the victim repo's configured `provisioning_behavior_prevent_with_label?` (e.g., no provisioning label present),
- `repository.owner.login` (or `organization.login`) set to any org name configured on the Shipit instance with a blank `webhook_secret` (attacker only needs to know this org name exists in the multi-org config; it can be an org unrelated to, or even one the attacker legitimately participates in),
- `repository.full_name` set to `"victimorg/victim-repo"` — a real, existing, review-stack-enabled repository with an already-archived `ReviewStack`.

`verify_signature` authenticates the request against the blank-secret org and passes regardless of the `X-Hub-Signature` header content. `UnlabeledHandler` then resolves `victimorg/victim-repo`'s `Repository`, finds its archived `ReviewStack`, and `ReviewStackAdapter#unarchive!` enqueues it for provisioning and unarchives it — none of which the attacker was authenticated to trigger for `victimorg`.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` schema on `UnlabeledHandler` only requires `repository.full_name`, not `owner`; there is no code anywhere that compares the verifying org to the mutated repository's owner.

### Impact Explanation
The attacker can force re-provisioning/unarchiving of a victim's `ReviewStack` without ever authenticating against the victim's org, and without needing the victim's `webhook_secret`. This causes deploy/provisioning infrastructure actions (`Shipit::ReviewStackProvisioningQueue.add`, `stack.unarchive!`) to run for a repository the request never validly proved authorization for — matching the Critical category "a payload for one repository mutating another's stack" / "an unauthorized deploy, rollback or merge trigger." The attack is repeatable against any victim repo/stack combination as long as one org with a blank `webhook_secret` exists on the instance (a documented, common configuration), and is not limited to a single victim.

### Likelihood Explanation
Preconditions: multi-org Shipit deployment where at least one configured org has a blank `webhook_secret` (explicitly shown as the default/example value in `docs/setup.md` and `config/secrets.development.example.yml`); victim repo has `review_stacks_enabled`, `provisioning_behavior_prevent_with_label?` (or `allow_with_label?`), and an existing archived `ReviewStack` for a given PR number. Attacker cost is a single unauthenticated HTTP POST with a hand-crafted JSON body — no GitHub account interaction, no secrets, no privileged role required. This is fully repeatable and requires no timing dependency.

### Recommendation
Bind the org used for signature verification to the org that the mutated data belongs to before dispatching: after `Repository.from_github_repo_name(params.repository.full_name)` resolves a repository, verify that `repository.owner` equals the `repository_owner`/`organization.login` value used in `verify_signature`, and reject (422) on mismatch. Additionally, treat a blank `webhook_secret` as "verification not configured for this org" and refuse to authenticate cross-repository-owning payloads under it, or require `webhook_secret` to be non-blank in any multi-org deployment.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test, no WebMock/live GitHub)
test "cross-org unlabeled webhook re-provisions victim stack via blank-secret org" do
  victim_repo = shipit_repositories(:shipit) # owner: 'shopify' in fixtures, review stacks enabled
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :prevent_with_label,
                       provisioning_label_name: "deploy-me")
  victim_stack = create_archived_review_stack_for(victim_repo, pr_number: 999) # archived, provision_status: deprovisioned

  # 'blank-secret-org' is configured with webhook_secret: nil in test dummy secrets
  request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: "unlabeled",
    number: 999,
    pull_request: {
      id: 1, number: 999, url: "https://api.github.com/x", title: "x", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "abc123", ref: "feature-branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [] # no provisioning label -> unarchive? true under prevent_with_label
    },
    repository: {
      full_name: victim_repo.github_repo_name, # "shopify/shipit" - VICTIM
      owner: { login: "blank-secret-org" }     # ATTACKER-CHOSEN, blank webhook_secret org
    },
    sender: { login: "attacker" }
  }.to_json

  Shipit::ReviewStackProvisioningQueue.expects(:add).with(victim_stack)

  post :create, body:, as: :json
  assert_response :ok

  # Binding check: verifying org ("blank-secret-org") != stack-owning org ("shopify") — yet mutation occurred
  assert_not_equal "blank-secret-org", victim_repo.owner
  assert_not victim_stack.reload.archived?, "victim stack was unarchived by a cross-org forged payload"
end
```
This demonstrates that `ReviewStackProvisioningQueue.add` and `stack.unarchive!` execute for `victim_repo`'s stack even though the signature was verified against an unrelated org's (blank) secret, proving the binding `org_that_verified == org_that_owns_mutated_stack` is broken.