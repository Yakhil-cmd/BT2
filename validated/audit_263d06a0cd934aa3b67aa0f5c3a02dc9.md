### Title
`pull_request` webhook signature is verified against `repository.owner.login`'s org secret while the handler mutates the stack resolved from the independent `repository.full_name` field, allowing cross-org state manipulation - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to verify with using only `repository.owner.login` (via `repository_owner`), while `UnlabeledHandler#repository` resolves the actual repository/stack to mutate using the entirely separate `repository.full_name` field. Because these two payload fields are never cross-checked, an attacker can pick an org with no configured `webhook_secret` (or one they control) for `repository.owner.login`, and point `repository.full_name` at a victim's real repository, causing the signature check to pass trivially while the handler archives/unarchives a stack it never authenticated for.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`org_used_to_verify_signature == org_that_owns_the_mutated_repository`, i.e. `params.dig('repository','owner','login') == Repository.from_github_repo_name(params.dig('repository','full_name')).owner`.

Path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads only `params.dig('repository','owner','login')` [1](#0-0) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org has no `webhook_secret` configured: `return true unless webhook_secret` [2](#0-1) . So naming a no-secret org in `repository.owner.login` makes signature verification a no-op, and even with a secret, the attacker only needs to know/possess the secret for the *unrelated* org they name, not the victim org's secret.
3. Once verification passes, `UnlabeledHandler#repository` resolves the repository purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` — a field completely decoupled from the one used for authentication [3](#0-2) .
4. `handle` then calls `stack.archive!` or `stack.unarchive!` on the review stack resolved from that repository [4](#0-3) .

Exploit request: a `pull_request` webhook with headers `X-Github-Event: pull_request`, `X-Hub-Signature` computed for (or simply irrelevant to) a no-secret org, and a JSON body where `repository.owner.login = "attacker-no-secret-org"` but `repository.full_name = "victim-org/victim-repo"`, `action = "unlabeled"`, `pull_request.state = "open"`, and labels chosen so `archive?`/`unarchive?` evaluates true for the victim repository's configured `provisioning_behavior`.

Existing guards do not catch this: `verify_signature` never compares `repository.owner.login` to `repository.full_name`'s owner segment; the `ExplicitParameters` schema for `UnlabeledHandler` only requires `repository.full_name` to be a `String`, with no relation asserted to the top-level owner used for auth [5](#0-4) . `GithubOrganizationUnknown` only fires if the named owner org isn't configured at all, which the attacker avoids by naming a real, known, no-secret (or attacker-known-secret) org.

### Impact Explanation
This lets an unauthenticated attacker force `stack.archive!` or `stack.unarchive!` on any review stack belonging to any repository, chosen purely by supplying its `full_name`, without possessing that repository's webhook secret. Archiving/unarchiving affects deploy gating logic downstream (e.g., stacks blocked by `blocking_statuses`, whose `blocked?` state and deployability can be toggled by side effects of archive/unarchive transitions). This is a payload targeting one repository (the attacker's own, no-secret org) mutating another repository's stack record — matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any repository whose `full_name` the attacker knows and which has review stacks enabled, and cross-tenant in that no relationship between the attacker's named org and the victim org is required.

### Likelihood Explanation
Preconditions: the victim repository must have `review_stacks_enabled` and a `provisioning_behavior` of `allow_with_label` or `prevent_with_label` (so `archive?`/`unarchive?` can trigger) — this is a supported, common Shipit configuration. The attacker needs only: (a) knowledge of any org name configured in Shipit without a `webhook_secret`, or an org whose secret they know (e.g., their own GitHub org integrated with the same Shipit instance), and (b) the victim's `owner/repo` full name, which is public information. No Shipit session, API token, or victim secret is required. This is a single unauthenticated `POST /webhooks` request, fully scriptable and repeatable at will.

### Recommendation
In `WebhooksController#verify_signature` (or in the handler base class), require that the org resolved from `repository.full_name` match `repository.owner.login`, and/or select the signing organization/repo consistently from the same field used to look up the target Repository/Stack. Reject the webhook if these diverge. Additionally, consider making `verify_webhook_signature` fail closed (require a secret) rather than default to `true` when no secret is configured for an organization that owns real repositories.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Fixtures: create `Repository` `victim-org/victim-repo` with `review_stacks_enabled: true`, `provisioning_behavior: allow_with_label`, and an associated `ReviewStack` in an unarchived state, tied to a `Stack` with `blocking_statuses` configured.
2. Configure Shipit github orgs so `"attacker-org"` has no `webhook_secret` (or stub `Shipit.github(organization: "attacker-org")` to return a `GitHubApp` whose `verify_webhook_signature` returns true unconditionally), while `"victim-org"` has a real, unknown-to-attacker `webhook_secret`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, arbitrary/no valid `X-Hub-Signature`, body:
```json
{
  "action": "unlabeled",
  "number": 1,
  "pull_request": { "state": "open", "labels": [], "head": {"sha":"...", "ref":"..."}, "user": {"login":"attacker"}, "assignees": [], ... },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
4. Assert: response is `:ok` (signature check passed via `attacker-org`); then assert `victim_review_stack.reload.archived?` (or `unarchived?`, per `provisioning_behavior`) changed as a direct result — proving `repository_owner used for auth ("attacker-org") != owner segment of full_name ("victim-org")` yet the victim stack was mutated, and that this occurred while the victim stack's `blocking_statuses`/`blocked?` gating was live.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
