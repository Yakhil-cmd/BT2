### Title
Cross-organization webhook signature confusion allows unauthorized writes to another tenant's repository/stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (as documented in `config/secrets.development.example.yml`, each GitHub org gets its own `app_id`/`webhook_secret`), the webhook signature check authenticates against one payload field while every event handler acts on a different, independently-controlled field of the same attacker-supplied JSON body. An attacker who owns one configured GitHub organization (and therefore legitimately knows/can produce a valid HMAC signature with that org's `webhook_secret`) can forge a webhook body whose `repository.full_name` points at a completely different organization's repository, and Shipit will process it as authentic.

### Finding Description
`WebhooksController#verify_signature` selects which org's secret to validate the signature against using `repository_owner`, taken from `repository.owner.login` (or `organization.login`): [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` picks the per-organization `webhook_secret` from configuration, matching the multi-org config schema documented in `config/secrets.development.example.yml`. The HMAC is verified over the *entire raw request body* with that org's secret: [3](#0-2) 

Once the signature check passes, every downstream handler resolves the target repository/stack from a **different field** in the same body: `repository.full_name`, not `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

For a genuine GitHub-originated webhook, `repository.owner.login` and the owner segment of `repository.full_name` are always consistent because GitHub itself populates both. But here the payload is entirely attacker-constructed JSON POSTed directly to `/webhooks`; nothing ties the two fields together except GitHub's own trustworthiness, which is bypassed. The binding that should hold is:

`organization authenticated (repository.owner.login, used to select the webhook_secret) == organization that owns the repository actually written (owner segment of repository.full_name, used by Repository.from_github_repo_name)`

This equality is never checked. An attacker who controls organization `attacker-org` (and thus its `webhook_secret`, e.g., because they are an admin of their own GitHub App installation on a shared multi-tenant Shipit instance) can sign a payload where `repository.owner.login == "attacker-org"` (so the signature validates) while `repository.full_name == "victim-org/victim-repo"` (so the handler acts on the victim's Shipit-tracked stack).

### Impact Explanation
This directly breaks a credential/organization boundary and results in cross-repository writes with only the attacker's own (legitimately obtained) webhook secret. Concretely, once past `verify_signature`, handlers keyed off `repository.full_name` can:
- Enqueue `GithubSyncJob`/create commits and `Status` records against another organization's stack (`push_handler.rb`, `status_handler.rb`) — spoofed CI/commit statuses can alter deployability and downstream automatic/continuous deployment decisions for a repository the attacker doesn't own.
- Create/close/merge review stacks against another organization's repository through the `pull_request/*` handlers (`opened_handler.rb`, `closed_handler.rb`, `review_stack_adapter.rb`), including provisioning/deprovisioning review-app infrastructure for a repo the attacker has no access to.

This matches the required "Critical" bar of cross-repository writes / an unauthorized deploy or merge, achieved purely by exploiting a mismatch between the field used for authentication and the field used for authorization, with no privileged Shipit session, API token, or the victim organization's own webhook secret required.

### Likelihood Explanation
Exploitability depends on the Shipit instance being configured for multiple GitHub organizations sharing one webhook endpoint — a supported and documented configuration (`config/secrets.development.example.yml` explicitly shows the multi-org schema, and `docs/setup.md` documents per-organization webhook secrets). In that documented topology, any org owner in the multi-tenant deployment is an "unprivileged attacker" relative to every other org's repositories, and can trivially construct and POST an arbitrary JSON body with a self-signed HMAC. No secret-guessing, session, or GitHub App private key access is required — only the attacker's own already-known `webhook_secret`.

### Recommendation
After signature verification succeeds, re-derive the organization identity strictly from the same field(s) the signature was keyed on, and require that `repository.full_name`'s owner segment (and/or `organization.login`) match `repository_owner` exactly before any handler resolves or mutates a `Repository`/`Stack`. Reject the payload (422) on mismatch instead of trusting `full_name` independently. Consider also binding the configured GitHub App's installation ID to the specific set of repository IDs it is allowed to reference, rather than trusting owner strings pulled from the untrusted payload body.

### Proof of Concept
1. Configure Shipit for two GitHub orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (per the documented multi-org schema).
2. Ensure `victim-org/victim-repo` already exists as a Shipit `Repository`/`Stack`.
3. As the attacker (who legitimately knows `attacker-org`'s `webhook_secret`), construct a `push` (or `status`/`pull_request`) event JSON body:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     ...
   }
   ```
4. Compute `X-Hub-Signature` as `sha1=HMAC(attacker-org_webhook_secret, raw_body)`.
5. POST to `/webhooks` with header `X-Github-Event: push` (or `status`, `pull_request`).
6. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret.
7. `PushHandler`/`StatusHandler`/`PullRequest::OpenedHandler` resolve `Repository.from_github_repo_name("victim-org/victim-repo")` and act on `victim-org`'s stack (enqueue sync jobs, write commit statuses, provision/close review stacks) — despite the attacker never possessing `victim-org`'s webhook secret or any Shipit credentials for that repository.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```
