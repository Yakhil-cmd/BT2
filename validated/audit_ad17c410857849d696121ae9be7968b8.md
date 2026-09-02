### Title
Cross-organization webhook forgery leads to unauthorized `GithubSyncJob` triggering on victim repositories in multi-GitHub-App deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App Shipit deployment (documented in `docs/setup.md`, section "Using Multiple Github Applications"), `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the signature against using a field taken directly from the *unverified* request body, while the event handlers dispatch on a *different* field of the same untrusted body to decide which repository/stack to act on. Nothing enforces that these two fields refer to the same organization, breaking the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App (and therefore the HMAC secret used to validate `X-Hub-Signature`) based on `repository_owner`, which is read straight from the JSON body before any signature check has occurred: [1](#0-0) [2](#0-1) 

Once the signature "passes" (i.e., matches the secret for whatever organization the attacker named), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw, attacker-controlled `params` to event handlers. Those handlers determine the target `Repository`/`Stack` using a *different* payload path, `repository.full_name`, via the shared `Handler#repository_name` helper: [3](#0-2) 

For example, `PushHandler` looks up all non-archived stacks for that repository/branch and immediately calls `stack.sync_github(expected_head_sha: params.after)`: [4](#0-3) 

Because `verify_signature` only checks that the signature is valid for the organization named in `repository.owner.login` (or falls back to `organization.login`), an attacker who legitimately administers **one** GitHub App/org configured in Shipit's multi-org `secrets.github` (and thus knows that org's `webhook_secret`, since org admins configure it themselves per `docs/setup.md`) can craft a payload where:
- `repository.owner.login` = their own org (used only to select which secret is checked), and
- `repository.full_name` = `"victim-org/victim-repo"` (used by the handler to pick the actual `Stack`/`Repository` to mutate).

Since the HMAC is computed over the full raw body, the attacker signs the crafted body with their own known secret; `verify_signature` re-derives the *same* org from the same body and confirms the signature, oblivious to the fact that the handler will act on an entirely different repository. There is no code path that checks `repository.owner.login == repository.full_name.split('/').first` or that otherwise ties the verified org to the acted-upon repository.

### Impact Explanation
This breaks the trust boundary between organizations sharing a single Shipit instance in a multi-GitHub-App setup. An attacker who controls a legitimate GitHub App installation for org A (and hence knows org A's `webhook_secret`) can forge webhooks that are processed as if they came from org B's repositories, e.g. forcing `PushHandler` to invoke `stack.sync_github(expected_head_sha:)` on a victim's stack with an attacker-chosen `expected_head_sha`, or triggering `CheckSuiteHandler`/`StatusHandler` side effects tied to arbitrary commits in a stack the attacker does not own. This is a cross-organization/cross-repository write inside the engine driven purely by request-body content that was never actually authenticated for that repository — matching the report's root cause (an unchecked binding that should have been enforced but wasn't) applied to Shipit's own webhook trust model.

### Likelihood Explanation
This only manifests when a Shipit deployment uses the multi-organization GitHub App configuration (each org has its own app/secret) as documented, and the attacker must genuinely control one configured org's webhook secret (i.e., they administer a GitHub App that the Shipit operator has added to `secrets.github`). This is a realistic scenario for shared/internal Shipit deployments serving multiple business units or teams, where each team manages its own GitHub App but shares the platform — no GitHub-side privilege on the victim's org or repo is required, only knowledge of one's own configured secret and the ability to send an HTTP POST to `/webhooks`.

### Recommendation
Cross-validate the organization used to select the verifying GitHub App against the organization implied by the repository actually being acted on before dispatching to handlers — e.g., derive both from the same nested payload path and reject if `repository.full_name`'s owner segment does not match `repository.owner.login`/`organization.login`, or scope handler repository lookups to the same `github_app`/organization context that successfully verified the signature, rather than re-reading raw payload fields independently in `Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `attacker-org` (secret `S_A`, known to the attacker) and `victim-org` (secret `S_V`, unknown to attacker), each with a `Stack` tracking a repository.
2. Attacker crafts a push payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against `S_A`.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack — an action the attacker was never authorized to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
