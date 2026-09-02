### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on `repository.full_name` — cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a GitHub webhook against using `repository.owner.login` (or `organization.login`) from the unverified JSON body. Every event `Handler`, however, resolves the target `Stack`/`Repository` using a completely different field of the same unverified body: `repository.full_name`. Because the HMAC signature only proves "this body was signed with organization X's secret," and nothing cross-checks that `repository.full_name`'s owner segment equals the `owner.login` used for that signature check, an attacker who legitimately possesses one organization's webhook secret can forge an event that is routed to and acts on a Stack belonging to a *different* organization.

### Finding Description
`verify_signature` picks the verifying `GitHubApp` based on `repository_owner`: [1](#0-0) [2](#0-1) 

Once the signature passes, the full parsed body is dispatched unchanged to the matching handler: [3](#0-2) 

Every `Handler` subclass resolves the affected repository/stack from a *different* JSON key, `repository.full_name`, with no correlation back to the `owner.login` value that was actually authenticated: [4](#0-3) 

`PushHandler`, for example, uses that (unauthenticated w.r.t. ownership) `stacks` scope together with attacker-supplied `ref`/`after` to trigger a sync: [5](#0-4) 

In a multi-organization deployment, each org gets its own `webhook_secret` precisely so that one organization cannot act on another's stacks — see the "Using Multiple Github Applications" configuration described in `docs/setup.md` and `lib/shipit.rb#github_app_config`. The equality the app is supposed to enforce is:

`organization whose secret signed the request == organization that owns the repository the handler mutates`

Because `owner.login` (used to pick the secret) and `full_name` (used to pick the target Stack) are two independent, attacker-controlled fields inside the same unsigned-at-parse-time JSON structure, this equality is never actually checked. An attacker who legitimately administers/installs the Shipit GitHub App for **their own** organization (and thus knows that org's `webhook_secret`) can set `repository.owner.login` to their own org (to pass signature verification) while setting `repository.full_name` to `"<victim-org>/<victim-repo>"` (to select a victim Stack).

### Impact Explanation
This breaks the organization-authentication vs. repository-written binding. A push event forged this way calls `stack.sync_github(expected_head_sha: params.after)` for a Stack the attacker does not own, using an attacker-chosen `ref`/`after` SHA and no legitimate authorization from the victim organization's GitHub App. Depending on the victim stack's continuous-deployment configuration, this can trigger unwanted syncs/deploys against a repository the attacker never had write access to, constituting a cross-repository/cross-organization write that Shipit's per-org secret isolation was explicitly designed to prevent. This matches the "cross-repository writes / unauthorized deploy" Critical-impact category.

### Likelihood Explanation
Medium: the attack requires a Shipit instance configured with the multi-org `github:` schema (documented and supported), and requires the attacker to hold a valid `webhook_secret` for at least one organization served by that instance — which is a normal, unprivileged capability for anyone who administers a GitHub App installation on any one of the tenant organizations, not a privilege over the victim organization.

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), enforce that the organization used to select/verify the webhook secret is the same organization that owns the repository/stack the handler is about to mutate — e.g., derive `repository_owner` from the same `full_name` field used by handlers (`full_name.split('/').first`), or have each `Handler` re-validate that the resolved `Repository`'s owner matches the authenticated organization before acting.

### Proof of Concept
1. Shipit configured multi-org, with `orgB.webhook_secret = X` (attacker's own org) and `orgA.webhook_secret = Y` (victim org, unknown to attacker).
2. Attacker (owner of the GitHub App installed on `orgB`) crafts:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "orgA/target-repo",
    "owner": { "login": "orgB" }
  }
}
```
3. POST to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature: sha1=HMAC(X, body)`.
4. `verify_signature` reads `repository_owner = "orgB"`, fetches `orgB`'s `GitHubApp`, and the signature validates successfully.
5. `create` dispatches to `PushHandler`, which resolves `stacks` via `repository.full_name = "orgA/target-repo"` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a Stack belonging to `orgA`, despite the request never being authenticated by `orgA`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
