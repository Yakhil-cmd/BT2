### Title
Webhook signature is verified against the organization named in the payload, but the write is performed against whatever `repository.full_name` the same payload claims — organization-authenticated ≠ repository-written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the attacker-controlled JSON body, then hands the *entire same payload* to the event handlers, which independently derive the target `Repository`/`Stack` from `repository.full_name` in that same body. Nothing ties the two fields together, so a payload can be legitimately signed for organization A while acting on organization B's repository.

### Finding Description
`verify_signature` computes the signing organization purely from request data: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `webhook_secret` configured for that organization (Shipit explicitly supports multiple GitHub orgs/apps in one instance, each with its own secret — see `docs/setup.md`/`config/secrets.development.example.yml`'s multi-org example), and `verify_webhook_signature` only checks the HMAC against that org's own secret: [3](#0-2) 

Once verification passes, the raw JSON body is dispatched unchanged to every registered handler for the event: [4](#0-3) 

The base `Handler` class, and concrete handlers such as `PushHandler`, resolve the target repository/stack from a *different* field of the same payload — `repository.full_name` — with no cross-check against `repository.owner.login`/`organization.login` that was used for signature verification: [5](#0-4) [6](#0-5) 

**Equality that should hold but doesn't:** `organization used to verify signature == organization owning the repository that gets written to`. Before the attack, both fields naturally match because GitHub itself populates them consistently. After the attack, an operator of a Shipit instance configured with multiple GitHub Apps/organizations (per the documented multi-org config) can send a payload where `repository.owner.login` = "org-they-control" (so the signature check passes with their own legitimately-obtained `webhook_secret`) while `repository.full_name` = "victim-org/victim-repo" (an org/repo they do not control). The handler acts on the victim repository's stacks regardless of which org's secret validated the request.

### Impact Explanation
This breaks the credential-to-resource binding the signature is supposed to enforce: possessing a valid webhook secret for organization A is treated as authorization to trigger side effects against organization B's stacks. Concretely, with a forged/mismatched `push` payload this reaches `PushHandler#process`, calling `stack.sync_github(expected_head_sha: params.after)` on stacks belonging to a completely different (victim) repository/organization than the one whose secret signed the request — an unauthorized cross-repository action driven entirely by an unprivileged attacker who legitimately controls just one small org's webhook secret. Other handlers keyed the same way (`status`, `check_suite`, `pull_request`, `membership`) are equally reachable and can create/modify commit statuses, check runs, teams, and memberships attributed to the victim stack. This matches the "cross-repository writes" / "unauthorized deploy" class of impact called out in scope.

### Likelihood Explanation
Requires only that the Shipit instance is configured with more than one GitHub organization/App (a documented, supported configuration) and that the attacker controls (or has webhook-secret access to) at least one of those configured organizations — no privileged Shipit account, `ApiClient` token, or GitHub write access to the victim repository is needed. This is a realistic operating mode for shared/multi-tenant Shipit deployments.

### Recommendation
After signature verification, require that the organization/owner used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the organization implied by `repository.full_name` (and, more generally, that the `Repository` resolved by handlers belongs to the same GitHub App/organization whose secret validated the request) before dispatching to handlers. Alternatively, bind each `Repository` record to the specific GitHub App/organization it was configured under and reject any webhook whose verified organization does not own the repository named in the payload.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (attacker controls the GitHub App and thus knows its `webhook_secret`) and `victim-org` (hosts the real target stack), per the multi-org config shown in `config/secrets.development.example.yml`.
2. Craft a `push` event payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=...` using `attacker-org`'s known `webhook_secret` (`app/controllers/shipit/webhooks_controller.rb:24-30` looks up the secret using `repository.owner.login` == `attacker-org`, and `lib/shipit/github_app.rb:76-83` validates the HMAC against that secret only — it passes).
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves stacks via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), and calls `stack.sync_github` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the request being cryptographically authenticated only for `attacker-org`.

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
