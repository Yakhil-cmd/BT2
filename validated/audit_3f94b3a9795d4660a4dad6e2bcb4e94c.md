### Title
Webhook signature is verified against `repository.owner.login`, but the handler acts on the independent `repository.full_name` field — cross-organization stack sync/deploy trigger - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) out of the still-unverified JSON body, then verifies the raw body against that organization's `webhook_secret`. However, once the signature check passes, `Shipit::Webhooks::Handlers::Handler#repository_name` (used by every handler, including `PushHandler`) resolves the target `Repository`/`Stack` from a *different*, independently-controlled field in the same body: `repository.full_name`. These two fields are never checked for consistency, so a payload can be crafted where the "authenticating" owner and the "acted-upon" repository refer to two different organizations.

### Finding Description
- `verify_signature` picks the app/secret via `repository_owner`, derived straight from the parsed, unverified request body: [1](#0-0) [2](#0-1) 
- The HMAC check only proves "this body was signed with OrgA's webhook secret" — it says nothing about which repository the body claims to describe.
- After the signature passes, `Handler#stacks` / `#repository_name` resolve the affected `Stack` using `payload.dig('repository', 'full_name')`, a sibling field of `repository.owner.login` inside the same JSON object, with no cross-check that this repository belongs to the organization that was authenticated: [3](#0-2) 
- `PushHandler#process` then directly triggers a sync (and, by extension, continuous-deployment logic downstream in `Stack#sync_github`) for whichever stacks match that attacker-chosen `repository.full_name`: [4](#0-3) 

This mirrors the analog bug class exactly: a value is *authenticated* (the organization associated with the signing secret) while a *different* value drawn from the same payload is the one actually acted upon (the repository whose stacks get synced/deployed). The equality that should hold — `authenticated_organization == owner_of(acted_upon_repository)` — is never enforced.

### Impact Explanation
The GitHub App webhook endpoint (`/webhooks`) is deliberately public/unauthenticated to the internet (webhook secret is the only gate) and is designed to serve multiple independently-onboarded GitHub organizations when `Shipit.github` is configured with a per-organization secret map (as documented for "Using Multiple GitHub Applications"): [5](#0-4) 

An attacker who legitimately installs the Shipit GitHub App on their **own** organization (an unprivileged, self-service action any GitHub org owner can perform, no Shipit credentials required) obtains a valid webhook secret for that organization. They can then send a `push` webhook to Shipit's public endpoint with `repository.owner.login` set to their own org (satisfying the signature check) but `repository.full_name` set to an arbitrary victim organization/repo that also has a Shipit stack configured. Because `PushHandler` never checks that `full_name`'s owner matches the authenticated `repository_owner`, this triggers `GithubSyncJob`/`stack.sync_github` for the victim's stack, and if that stack has continuous deployment enabled, it can cause an unauthorized sync/deploy trigger for a repository the attacker does not control — crossing the "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires only: (1) the deployment to be configured for multiple GitHub organizations (a documented, supported configuration), and (2) the attacker being able to install the shared Shipit GitHub App on an organization they control to obtain a valid webhook secret — no Shipit session, API token, or privileged account needed. This is a realistic configuration for any multi-tenant Shipit deployment.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (the field actually used to resolve stacks) and reject the webhook (422) unless it matches the organization whose secret was used to verify the signature (`repository_owner`). Alternatively, verify the payload only against the secret of the organization that owns the target repository, computed once and used consistently for both signing verification and stack resolution.

### Proof of Concept
1. Attacker installs the shared Shipit GitHub App on `attacker-org`, obtaining a valid `webhook_secret` for it (per `docs/setup.md` multi-org setup, this is a legitimate/normal, unprivileged action).
2. Attacker crafts a `push` event JSON body:
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
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, looks up `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully.
5. `Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("victim-org/victim-repo")` — unrelated to `attacker-org` — and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack, without any check that `victim-org` matches the authenticated `attacker-org`.

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

**File:** docs/setup.md (L182-209)
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
