Based on the investigation, this analog exists: the webhook signature is verified against an organization derived from one payload field, while the actual repository/stack acted upon is derived from a different, unrelated payload field.

### Title
Webhook signature verification binds to `repository.owner.login`, but the repository acted upon is taken from the unrelated `repository.full_name` field, allowing cross-organization stack sync - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to check the `X-Hub-Signature` against using `repository.owner.login` (or `organization.login`) taken from the untrusted, attacker-supplied JSON body. Once the signature validates, the actual event handlers (e.g. `PushHandler`) resolve which `Repository`/`Stack` to act on using a completely different field of the same body: `repository.full_name`. Nothing enforces that these two fields refer to the same repository/organization.

### Finding Description
`verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This picks the HMAC secret to validate the whole raw body against based solely on `repository.owner.login`, a field controlled entirely by the request body.

Once the signature check passes, `Handler#stacks` — used by every event handler including `PushHandler` — resolves the target repository from a *different* field of the same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`PushHandler#process` then triggers a real sync using an attacker-chosen `after` sha for every matching stack/branch:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [3](#0-2) 

There is no code anywhere that asserts `repository.owner.login` (the field used to pick the signing secret) matches the owner segment of `repository.full_name` (the field used to pick the target `Stack`). Since Shipit supports multiple GitHub organizations, each with its own `webhook_secret` fetched via `Shipit.github(organization:)`, an entity that legitimately controls Organization A's GitHub App (and therefore knows Organization A's own `webhook_secret`) can craft a payload where `repository.owner.login = "OrgA"` (so the signature validates against OrgA's secret) but `repository.full_name = "OrgB/target-repo"` (so the handler acts on OrgB's stack). This breaks exactly the binding: *the organization whose signature authenticated the request* vs. *the repository that is actually written to*.

### Impact Explanation
This lets a party who only has legitimate webhook credentials for their own, unrelated GitHub organization force a `GithubSyncJob` (and thus commit ingestion / deploy-spec cache recompute) against a completely different organization's stack, by forging the `after`/`ref` fields. Depending on downstream trust of synced commits (e.g. auto-deploy of newly appended commits when `continuous_delivery` is enabled), this can cause an unauthorized deploy trigger on a stack the caller has no relationship to — matching the "unauthorized deploy" / cross-repository write impact category.

### Likelihood Explanation
Exploitability only requires the attacker to control (or know the webhook secret of) any single organization already integrated with the Shipit instance — not privileged access to the target organization or a Shipit session/token. In any Shipit deployment onboarding multiple independent organizations/tenants, this is directly reachable via the public, unauthenticated `/webhooks` endpoint.

### Recommendation
Derive both the signing-secret lookup and the target-repository lookup from the *same* trusted field, and additionally verify that `repository.owner.login` matches the owner segment parsed from `repository.full_name` before dispatching to handlers; reject the payload otherwise.

### Proof of Concept
1. Shipit hosts stacks for `OrgA/repo1` and `OrgB/repo2`, each configured with its own `webhook_secret`.
2. Attacker legitimately controls `OrgA`'s GitHub App / webhook secret (e.g. is an admin of OrgA, not OrgB).
3. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-in-OrgB/repo2>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/repo2" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully using OrgA's own secret.
6. `PushHandler` resolves `repository_name = "OrgB/repo2"`, finds OrgB's real stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, forcing a sync/deploy-spec-cache cycle on OrgB's stack that OrgA has no authorization over.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
