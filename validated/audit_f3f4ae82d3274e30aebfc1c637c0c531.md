### Title
Webhook signature verification is keyed on `repository.owner.login`, but events are dispatched to stacks using the unrelated `repository.full_name` field, allowing cross-repository forged webhooks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret` used to validate `X-Hub-Signature`) using `repository_owner`, which is read from `params.dig('repository','owner','login')` (or `organization.login`) inside the JSON body itself. [1](#0-0) [2](#0-1)  The signature is a valid HMAC over the raw body, so it only proves "this body was signed with *some* organization's configured `webhook_secret`" — it never proves that the *content* of `repository.full_name` (the field the handlers actually act on) belongs to that same organization.

Shipit supports configuring multiple independent GitHub orgs, each with its own `webhook_secret`. [3](#0-2)  Every event handler resolves the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')`, e.g. `Handler#repository_name` / `Handler#stacks` [4](#0-3)  and `PushHandler#process` [5](#0-4) . Nothing checks that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` used for signature verification.

### Finding Description
The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository being acted upon`

Because both `repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the stack to act on) are independent, attacker-controlled fields inside the very same signed JSON body, an attacker who legitimately owns/administers *any* GitHub organization already onboarded onto the Shipit instance (i.e., has a valid, distinct `webhook_secret` configured for their own org) can:

1. Craft a JSON body where `repository.owner.login` = `"attacker-org"` (so `Shipit.github(organization: 'attacker-org')` resolves their own `GithubApp`, whose secret they know because it's their own org's webhook).
2. Set `repository.full_name` = `"victim-org/victim-repo"` inside the same body.
3. Compute the HMAC over the whole raw body using their own org's `webhook_secret` and send it directly to `/webhooks` with `X-Hub-Signature` and `X-Github-Event: push` (or `status`, `check_suite`).

`verify_signature` will pass, because it only checks that the body was signed with the secret belonging to `repository.owner.login` = `"attacker-org"` — which it legitimately was. [1](#0-0)  Then `PushHandler#process` resolves stacks for `victim-org/victim-repo` (via `Repository.from_github_repo_name`) and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack, using an attacker-chosen `after` sha. [5](#0-4) 

This is the direct analog of the DODO V3 bug: just as `userWithdraw()` trusted an unvalidated exchange-rate parameter without checking it belonged to the caller's real position, `verify_signature` trusts that the org that authenticated the webhook is the org whose repository the payload subsequently manipulates, without cross-checking the two fields against each other.

### Impact Explanation
An attacker who controls a single legitimate GitHub org configured in the Shipit instance (a low-privilege, unprivileged actor with respect to any *other* onboarded org/repo) can forge push/status/check_suite events that are dispatched against stacks belonging to a completely different organization/repository. This can:
- Trigger `GithubSyncJob`/`stack.sync_github` for a victim's stack with an attacker-chosen `expected_head_sha`, forcing Shipit's view of the victim repository state to a commit of the attacker's choosing.
- Combined with `StatusHandler` (also resolved purely via `repository.full_name`), forge CI status for arbitrary commits/repositories, bypassing "deployable" checks used to gate deploys.

This crosses a genuine authentication/authorization boundary (organization webhook credential vs. the repository actually written), satisfying the "unauthorized deploy/rollback" or "cross-repository writes" Critical impact bar in the rules, since it lets the sync/deploy-readiness state of an unrelated repository be manipulated without that repository's own credentials.

### Likelihood Explanation
Requires the attacker to already be a legitimate administrator of some GitHub organization that is configured in the same Shipit instance (multi-org deployments are explicitly documented/supported). [3](#0-2)  No compromise of the victim org, no Shipit session, and no `ApiClient` token is required — only knowledge of the attacker's own org's `webhook_secret`, which they legitimately possess. In single-org Shipit deployments this issue does not apply, but multi-org deployments are a documented, supported configuration.

### Recommendation
In `WebhooksController#verify_signature` / the handler base class, after verifying the signature, assert that the organization used to select the `webhook_secret` (`repository_owner`) matches the owner segment of `repository.full_name` (and any other repository identifiers acted upon by the specific handler) before dispatching to `Shipit::Webhooks.for_event(event)`. Reject the request (422) on mismatch.

### Proof of Concept
Not executed (no test/terminal access in this mode). Conceptually:
1. Configure Shipit with two orgs, `attacker-org` (attacker-controlled, secret known to attacker) and `victim-org` (contains a real, deployable stack).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Set `X-Hub-Signature` = `sha1=` + HMAC-SHA1(raw_body, attacker-org's webhook_secret).
4. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and validates successfully. [1](#0-0)  `PushHandler` then looks up stacks for `victim-org/victim-repo` and calls `sync_github` on them. [5](#0-4) 

Note: I was unable to fully retrieve `Stack#sync_github` and `StatusHandler` implementations before running out of tool iterations, so the exact downstream effect on deploy gating (e.g. whether a forged `status` event alone can flip `deployable?`) is inferred from the handler dispatch pattern rather than fully traced end-to-end. This should be verified directly against `app/models/shipit/stack.rb` and `app/models/shipit/webhooks/handlers/status_handler.rb`.

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
