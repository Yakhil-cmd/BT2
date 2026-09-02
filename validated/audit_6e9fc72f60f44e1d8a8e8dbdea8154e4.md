### Title
Webhook signature scoped by unauthenticated `repository.owner.login`, but event handlers dispatch on unauthenticated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate against by reading an **unauthenticated** field out of the JSON body (`repository.owner.login`, or `organization.login`), then HMAC-verifies the raw body against that org's secret. Every downstream `Webhooks::Handlers::Handler` subclass (e.g. `PushHandler`) instead resolves the target `Repository`/`Stack` using a *different* unauthenticated field in the same body: `repository.full_name`. Because the two fields are never cross-validated, a party who legitimately controls one configured GitHub organization's `webhook_secret` (by owning/installing the Shipit GitHub App on their own org, a normal, unprivileged multi-tenant setup per `docs/setup.md`'s "Using Multiple Github Applications" section) can forge a signed payload whose `repository.owner.login` names *their own* org (so the secret lookup and HMAC check succeed) while `repository.full_name` names a **victim** organization's repository, causing Shipit to sync/act on the victim stack.

### Finding Description
`verify_signature` computes the org used for secret selection from the payload itself, before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

The signature check itself only proves the raw body was HMAC-signed with *some* configured org's `webhook_secret` — it says nothing about which repository within that body is legitimate for that org: [3](#0-2) 

Once the request passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire unauthenticated JSON body* to handlers such as `PushHandler`, which resolve the target repository via a completely different key, `repository.full_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

This is the same class of bug as the Wormhole report: a field the code trusts for authorization decisions (`repository.owner.login`, analogous to Wormhole's destination chain ID selection) is not the field bound by the cryptographic guarantee that ultimately drives the privileged action (`repository.full_name`, analogous to the emitter chain actually acted upon). Both fields live in attacker-controlled JSON and are never checked against each other, so the "organization authenticated" and "repository that is written" are two independent, unverified equalities: `signature_org == payload['repository']['owner']['login']` while the actual write target is `stack == Repository.from_github_repo_name(payload['repository']['full_name'])`, with no constraint forcing `full_name`'s owner segment to equal the authenticated org.

### Impact Explanation
In the documented (and supported) multi-org configuration, each organization gets its own GitHub App and `webhook_secret`. An attacker who legitimately controls their own org's Shipit installation (and thus legitimately knows their own `webhook_secret`) can forge a `push` webhook body with `repository.owner.login` set to their own org (passing signature verification) but `repository.full_name` set to `victim-org/victim-repo`, an existing Stack registered by a different tenant on the same shared Shipit instance. This drives `PushHandler#process` to call `stack.sync_github(expected_head_sha: params.after)` against the victim's Stack with an attacker-chosen `after` SHA, enqueuing `GithubSyncJob` for that stack (`app/jobs/shipit/github_sync_job.rb`). This is a cross-organization/cross-repository write into another tenant's Stack state driven entirely by an unauthenticated attacker-controlled payload field, satisfying the "cross-repository writes" impact bar in a shared/multi-org Shipit deployment.

### Likelihood Explanation
Likelihood is low-to-moderate and configuration-dependent: it requires a Shipit deployment configured with multiple GitHub organizations (explicitly documented and supported) where the attacker legitimately controls at least one tenant org's app/webhook_secret while a victim stack from a different org exists on the same instance. In a single-organization deployment this analog collapses (there's only one secret/org, so `repository.owner.login` can't diverge from a *different* authenticated org). No session, API token, or GitHub write access to the victim repo is required — only knowledge of one's own legitimately-provisioned webhook secret and the target stack's `owner/repo` full name.

### Recommendation
Do not let handlers trust `repository.full_name` independently of the field used to select/verify the webhook secret. `verify_signature` (or the handlers) should re-derive/require that the org used to pick `webhook_secret` matches the owner segment parsed out of `repository.full_name` (and any other repository-identifying fields used by handlers) before dispatch, rejecting the request if they disagree — mirroring the Wormhole fix of binding the validated identifier to the one actually acted upon rather than trusting two independently-supplied, unauthenticated fields to agree.

### Proof of Concept
1. Configure Shipit in multi-org mode with `github.attacker-org.webhook_secret = S1` and `github.victim-org.webhook_secret = S2`, each per `docs/setup.md`.
2. Attacker (who owns `attacker-org`'s GitHub App/installation) knows `S1`.
3. Attacker creates a Stack is not required on their side; they only need to know a victim Stack's `owner/repo` (public in Shipit UI/URLs), e.g. `victim-org/victim-repo`, already tracked on the shared instance.
4. Attacker crafts body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/<victim-branch>",
  "after": "<attacker-chosen-sha>"
}
```
5. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(S1, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
6. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, verifies successfully using `S1` [1](#0-0) .
7. `PushHandler#process` resolves the stack via `repository.full_name = "victim-org/victim-repo"` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, enqueuing `GithubSyncJob` against the victim's stack.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
