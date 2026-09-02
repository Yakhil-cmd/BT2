### Title
Webhook Signature Verified Against `repository.owner.login` While Handlers Act on the Unrelated `repository.full_name` Field, Enabling Cross-Organization Forged Push/Deploy Triggers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `params.dig('repository', 'owner', 'login')`, but the event handlers that actually act on the payload (e.g. `PushHandler`) look up the target `Stack` using an entirely different field, `payload.dig('repository', 'full_name')`. Nothing in the code enforces that these two fields describe the same repository/organization. An attacker who controls (or administers) any organization with its own installed Shipit GitHub App — and therefore knows that organization's `webhook_secret` — can forge a webhook body whose `repository.owner.login` matches their own org (so it passes signature verification with a secret they legitimately possess) while setting `repository.full_name` to point at a completely different, unrelated repository/stack tracked by the same Shipit instance. Because the whole JSON body is attacker-authored before signing, both fields are equally attacker-controlled; the signature only proves "signed by org A's secret," not "this payload legitimately describes a commit to org A's repository."

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is derived here: [2](#0-1) 

The verification therefore only proves the raw body was HMAC-signed with the secret belonging to whichever organization `repository.owner.login` names.

However, the event handlers dispatched via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:12`) determine the actual repository/stack to act on using a *different* field: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` then syncs/deploys against any `Stack` matching that repository name and target branch: [4](#0-3) 

Nothing anywhere cross-checks that `repository.full_name`'s owner equals `repository.owner.login` (the value that was actually verified). The binding that should hold — `organization_that_authenticated == organization_of_repository_that_is_acted_upon` — is never enforced.

### Impact Explanation
An attacker who administers any organization with its own Shipit GitHub App installation (and thus knows that installation's `webhook_secret` — a routine, unprivileged capability for anyone who can install a GitHub App on their own org) can:
1. Craft a webhook JSON body with `repository.owner.login` set to their own organization (satisfies signature verification against their known secret).
2. Set `repository.full_name` inside the same body to reference an unrelated repository/stack tracked by the victim Shipit instance.
3. POST this forged, correctly-signed `push` event to the shared `WebhooksController#create` endpoint.

Because `verify_signature` never re-validates that `repository.full_name`'s owner matches the organization whose secret was used, the forged event is accepted, and `PushHandler` triggers `Stack#sync_github` for the victim repository/branch — which can drive continuous deployment or otherwise cause the target stack to sync against attacker-chosen commit SHAs. This is a cross-organization write / unauthorized-deploy-trigger crossing a trust boundary the signature was supposed to enforce, matching the "unauthorized deploy" impact criterion.

### Likelihood Explanation
Likelihood is significant in any multi-tenant Shipit deployment (the presence of `Shipit.github(organization:)` and the rescued `Shipit::GithubOrganizationUnknown` error indicates the engine is designed to support multiple organizations/GitHub App installations concurrently). Any org admin in such a deployment — an otherwise low-privilege actor with respect to *other* orgs' repositories — can mount this attack with a single crafted HTTP request; no GitHub push access to the victim repository, no Shipit session, and no victim secret are required.

### Recommendation
After signature verification, assert that the organization used to select the verifying `github_app` (`repository_owner`) matches the owner of `repository.full_name` used by the handlers, and reject the webhook if they diverge. Alternatively, derive `repository_owner` from the same `repository.full_name` field the handlers use, so a single canonical field governs both which secret verifies the signature and which repository is acted upon.

### Proof of Concept
1. Attacker creates/administers GitHub organization `attacker-org` and installs the Shipit GitHub App there, obtaining its `webhook_secret` (a normal, unprivileged action for one's own org).
2. Attacker builds a `push` event payload:
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
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over this exact raw body.
4. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and verifies successfully against the attacker's own secret.
6. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker-chosen-sha>')`, causing the victim stack to sync/deploy based on attacker-forged data — despite the signature never having been checked against any secret belonging to `victim-org`.

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
