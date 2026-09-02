### Title
Cross-Organization Commit Status Forgery via Unscoped `StatusHandler` Webhook Processing - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to validate the incoming webhook's HMAC signature based solely on the `repository.owner.login` field of the JSON payload, then dispatches the entire payload to event handlers. The `status` event handler, `StatusHandler`, never re-derives or checks which repository the webhook actually claims to originate from — it looks up commits globally by SHA across the whole Shipit instance. This breaks the binding between "the organization whose secret authenticated the webhook" and "the repository/stack whose commit is written."

### Finding Description
The signature check in the controller uses only the claimed owner login to pick the verifying secret: [1](#0-0) [2](#0-1) 

Shipit explicitly supports hosting multiple GitHub Apps/organizations in a single instance, each with its own independent `webhook_secret`: [3](#0-2) 

Once the signature is accepted for *some* organization, the full JSON body is handed unmodified to every registered handler for the event: [4](#0-3) 

Most handlers scope their side effects to the repository named in the payload via `Handler#stacks`/`repository_name`, which reads `repository.full_name`: [5](#0-4) 

However, `StatusHandler` does not use this scoping at all — it queries commits globally by SHA, independent of which repository/organization the payload claims: [6](#0-5) 

The equality broken: `organization authenticated (repository.owner.login used to select the webhook_secret)` ≠ `repository whose commit status is written (Commit.where(sha:) has no repository/organization constraint)`. `repository.owner.login` and `repository.full_name`/commit SHA are independent, attacker-controlled JSON fields in the same payload, and only the former is covered by the HMAC signature check's routing logic — neither is cross-validated against the other, nor is the SHA scoped to a repository owned by the authenticating organization.

### Impact Explanation
An attacker who legitimately owns/administers one GitHub organization hosted on a shared, multi-org Shipit instance (and therefore legitimately knows that organization's own `webhook_secret`) can forge a `status` webhook event: they set `repository.owner.login` to their own org (so `verify_signature` picks their own, known secret and passes), while setting `sha` to a commit SHA belonging to a completely different, victim-owned repository/stack tracked by the same Shipit instance (commit SHAs are public GitHub information). `StatusHandler#process` will then create/update a `Status` (e.g., `state: "success"`) on that victim commit, because the lookup is `Commit.where(sha: params.sha)` with no repository restriction. Since commit statuses are used by Shipit stacks to gate whether a commit is considered deployable, this can be used to force a victim commit to appear as passing CI/checks it never actually passed, enabling an unauthorized deploy decision on a repository/organization the attacker has no legitimate access to. This satisfies the "unauthorized deploy" / cross-repository-write class of impact.

### Likelihood Explanation
Likelihood is limited to instances configured with multiple GitHub Apps/organizations sharing one Shipit deployment (an explicitly documented and supported configuration), where the attacker is a legitimate holder of a webhook secret for only one of those organizations. Within that configuration, the attack requires no privileged Shipit credentials, only knowledge of a target commit SHA (obtainable from the public victim repository), making it straightforward to execute once the multi-org setup exists.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries by SHA/ID without repository scoping) to the repository named in the payload, consistent with the `Handler#stacks` helper used elsewhere, e.g.:
```ruby
def process
  stacks.commits.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Additionally, consider binding the verified webhook organization (used to pick the signing secret) to the `repository.owner.login`/`full_name` actually processed, rejecting webhooks where these are inconsistent.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret` values (per `docs/setup.md` multi-org config).
2. Attacker legitimately knows `attacker-org`'s `webhook_secret` (it's their own app).
3. Attacker obtains a real commit SHA `S` from a `victim-org` repository tracked by the same Shipit instance (public info).
4. Attacker sends a `status` webhook payload:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
5. Signs it with `attacker-org`'s `webhook_secret` in `X-Hub-Signature`.
6. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org`, fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature.
7. `StatusHandler#process` executes `Commit.where(sha: "S")`, finds the `victim-org` commit, and calls `create_status_from_github!`, marking it as `success` — despite the request never being authenticated against `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
