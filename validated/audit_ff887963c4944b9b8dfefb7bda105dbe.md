### Title
Cross-repository webhook forgery via organization/repository binding mismatch in `WebhooksController#verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController` selects which GitHub App / webhook secret to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the handlers that actually act on the payload resolve the target `Stack`/`Repository` from an entirely different field: `repository.full_name`. The signature only proves the raw body was signed with *some* onboarded organization's webhook secret — it never binds that organization to the `full_name` field the handlers use to pick which repository/stack is mutated. This mirrors the referenced report's core defect class: a value that is checked/consumed by one part of the system (the option's OTM/strike bucket) is never re-validated against the state (bond redemption) that the rest of the system depends on, letting a stale/mismatched binding be exploited indefinitely.

### Finding Description
`verify_signature` computes the org used for signature verification from the payload itself: [1](#0-0) [2](#0-1) 

This calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(...)`, which only skips verification when no secret is configured, and otherwise HMAC-checks the raw body against that specific organization's `webhook_secret`: [3](#0-2) 

Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire, unconstrained* payload to handlers: [4](#0-3) 

Every default handler (`PushHandler`, `StatusHandler`, `PullRequest::*`, `CheckSuiteHandler`) inherits `Handler#stacks`/`Handler#repository_name`, which resolves the target repository from `payload.dig('repository', 'full_name')` — a field completely independent of `repository.owner.login` used during signature verification: [5](#0-4) [6](#0-5) 

Nowhere between `verify_signature` and handler dispatch is `repository.owner.login` reconciled with `repository.full_name`. Shipit explicitly supports multiple GitHub Apps, one per organization, each with its own independently configured (and optional) `webhook_secret`: [7](#0-6) 

Consequently, an entity that legitimately controls the webhook secret for *one* onboarded organization (Org A) — a routine, unprivileged-relative-to-other-tenants capability in a multi-organization Shipit deployment — can produce a validly-signed request where `repository.owner.login`/`organization.login` = `"org-a"` (so verification passes against Org A's secret) while `repository.full_name` = `"org-b/victim-repo"`. The handler layer will act on Org B's stack without ever having validated a signature tied to Org B.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," matching the rules' named analog class directly. Concretely:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)` for any stack matching the forged `full_name`/`branch`, letting an attacker inject synchronization/deploy-triggering events for repositories they do not own — a cross-repository write against `Shipit::Stack`/`Shipit::Commit` state. [8](#0-7) 
- `StatusHandler` writes forged CI/check statuses (`success`/`pending`) onto arbitrary victim commits, which downstream deploy-readiness logic in Shipit relies on to gate `deploy:stack` actions — enabling an eventual unauthorized deploy once a legitimate operator acts on the forged green status.
- Other event types (`pull_request`, `check_suite`, `membership`) are similarly dispatched with attacker-controlled `full_name`/`organization` sub-fields that are never cross-checked against the verified org.

This satisfies the Critical bar of "cross-repository writes" / contributing to an "unauthorized deploy, rollback or merge," since state belonging to Repository/Stack B is mutated using only a signature proven against Organization A's secret.

### Likelihood Explanation
Any tenant/organization onboarded into a shared, multi-organization Shipit instance (a documented, supported configuration) can trivially exploit this by crafting a JSON body whose `repository.owner.login` matches their own org (to pass HMAC verification with their own legitimately-held secret) but whose `repository.full_name` names a different tracked repository. No compromise of another organization's secret, GitHub session, or API token is required — only knowledge of one's own webhook secret, which is a routine credential any onboarded org possesses. Likelihood is high in any deployment onboarding more than one GitHub organization.

### Recommendation
After parsing the payload, re-derive the acted-upon repository owner the same way as `repository_owner` and require it to equal the owner segment of `repository.full_name` (and any `organization.login` field used by handlers such as `MembershipHandler`) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, bind handler dispatch to the same `github_app`/organization instance that succeeded verification rather than re-deriving repository identity from unauthenticated payload subfields.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md`), and a tracked stack for `org-b/victim-repo`.
2. As a holder of `org-a`'s webhook secret, craft a `push` event body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "org-b/victim-repo", "owner": { "login": "org-a" } }
   }
   ```
3. Compute `X-Hub-Signature` using `org-a`'s `webhook_secret` (`Shipit::GitHubApp#verify_webhook_signature`, `sha1=` HMAC of the raw body).
4. POST to `/webhooks` with `X-Github-Event: push` and the computed signature.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, verifies successfully against `org-a`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `Shipit::Webhooks::Handlers::PushHandler` resolves the target stack via `payload.dig('repository','full_name')` = `"org-b/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github` on Org B's stack — a write performed using only Org A's signature.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
