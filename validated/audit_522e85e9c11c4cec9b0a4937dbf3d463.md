## Finding

### Title
Webhook signature verification is bound to `repository.owner.login`, but stack/repository mutations are bound to the unverified `repository.full_name` field, allowing cross-repository writes ([File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb])

### Summary
Shipit's webhook signature check authenticates a payload against the GitHub App config selected by `repository.owner.login` (or `organization.login`), while every handler that actually mutates state (creating commits, queuing syncs, closing/labeling PRs, updating statuses) selects its target `Stack`/`Repository` using a *different* field of the same payload: `repository.full_name`. These two fields are never cross-checked against each other. This is structurally the same class of bug as the sandwich-attack report: the value that is verified/authorized (the organization used to pick the HMAC secret) is not the value that is acted upon (the repository actually written to).

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization config to use for HMAC verification from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and `Shipit.github(organization: repository_owner)` is used purely to pick which webhook secret/App config to verify the HMAC signature against.

However, once the signature check passes, the actual handler logic that decides *what* gets mutated does not use `repository.owner.login` at all — it uses `repository.full_name`: [3](#0-2) 

`stacks` (used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s) resolves the target `Repository`/`Stack` solely from `payload.dig('repository', 'full_name')`, with no assertion that the owner segment of `full_name` matches `repository.owner.login` (the field that determined which secret validated the signature).

Since Shipit supports multiple GitHub organizations, each with its own App config/`webhook_secret` (`Shipit.github(organization:)` raises `GithubOrganizationUnknown` when the org isn't registered — i.e., there is a per-organization secret mapping), this creates the exact binding break the rules call out: **an organization that authenticated versus the repository that is written**.

Concrete attack: an attacker who is an authorized member/owner of "OrgA" (one of the organizations this Shipit instance trusts, with its own registered webhook secret) can send a request directly to the webhook endpoint with:
- `repository.owner.login` = `"OrgA"` / `organization.login` = `"OrgA"` — so `verify_signature` selects OrgA's webhook secret, and the attacker (as a legitimate OrgA member who can trigger real GitHub events or who knows/derives OrgA's own webhook secret through their own legitimate app installation) can produce a valid signature for arbitrary bytes signed with OrgA's secret.
- `repository.full_name` = `"OrgB/victim-repo"` — an unrelated repository/stack belonging to a different tenant/organization ("OrgB") of the same Shipit instance.

Because `repository_name` in `Handler` only reads `full_name` and never checks it against the owner that authenticated the request, the forged payload is processed as if it legitimately came from OrgB: e.g. `PushHandler` will enqueue `GithubSyncJob` for OrgB's stack with an attacker-chosen `after` SHA, `StatusHandler` will write commit statuses onto OrgB's commits, and the PR handlers will close/label/edit OrgB pull requests — all cross-repository writes performed with an authentication decision that was bound to a different repository owner than the one being mutated.

### Impact Explanation
This breaks a deployment-trust binding required by the rules: the entity that authenticated the webhook (OrgA, via its own webhook secret) is not the entity whose repository state is written (OrgB). This enables cross-repository writes — for example, forcing a `GithubSyncJob` to run against another tenant's stack with attacker-controlled commit metadata, injecting fabricated commit statuses, or manipulating another organization's pull requests/labels — without ever needing OrgB's webhook secret, a Shipit session, or repository write access to OrgB. This satisfies the Critical impact category "cross-repository writes."

### Likelihood Explanation
Exploitability requires only that the Shipit instance is configured to trust more than one GitHub organization (multi-tenant `github` config, evidenced by the per-organization lookup and `GithubOrganizationUnknown` handling) and that the attacker controls (or is a legitimate member of) at least one of those trusted organizations — a normal, unprivileged position relative to any *other* tenant's repository. No secrets, tokens, or GitHub App keys belonging to the victim organization are needed.

### Recommendation
When resolving the target repository/stack in `Handler#repository_name`/`#stacks`, cross-check that the owner segment of `repository.full_name` matches the `repository.owner.login`/`organization.login` value that was used to select the verifying webhook secret in `WebhooksController#verify_signature`, and reject the request (422) if they diverge.

### Proof of Concept
Conceptual request (assuming OrgA and OrgB are both configured GitHub orgs in `Shipit.github`):
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC computed with OrgA's webhook_secret over the exact body below>

{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "organization": { "login": "OrgA" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
`verify_signature` uses `repository.owner.login = "OrgA"` to fetch OrgA's secret and validates successfully (attacker knows/controls it). `PushHandler`/`Handler#stacks` then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and enqueues `GithubSyncJob` for OrgB's stack, per [4](#0-3)  — a write against a repository the authenticated organization does not own.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
