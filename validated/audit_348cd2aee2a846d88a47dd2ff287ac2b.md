## Title
Webhook signature verification authenticates one organization while handlers act on the repository named in an unrelated payload field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` must match the HMAC signature by reading `repository.owner.login` (or `organization.login`) from the JSON body. Every event handler, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same body: `repository.full_name`. Because the HMAC only proves the request was signed with *some* organization's secret, not that the acted-upon repository belongs to that organization, an attacker who legitimately administers **any** GitHub organization onboarded into a shared/multi-tenant Shipit instance can sign an arbitrary payload with their own org's webhook secret while setting `repository.full_name` to a completely unrelated, victim-owned repository tracked by the same Shipit instance.

### Finding Description
`verify_signature` derives the signing organization solely from the payload, independent from the repository the handler will later resolve: [1](#0-0) [2](#0-1) [3](#0-2) 

`Shipit.github(organization: repository_owner)` is looked up only from `repository.owner.login` / `organization.login`, and its `webhook_secret` is used to validate the HMAC over the raw body: [4](#0-3) 

But every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) resolves the actual `Repository`/`Stack` from a *separate* field, `repository.full_name`, via the shared `Handler` base class: [5](#0-4) 

`Repository.from_github_repo_name` just splits `"owner/name"` and does a DB lookup with no cross-check against the field used for signature verification: [6](#0-5) 

`PushHandler` then queues a full GitHub sync for whatever stacks match that resolved repository/branch: [7](#0-6) 

Nothing in this pipeline requires `repository.owner.login` (the field bound to the verified signature) to match the owner segment of `repository.full_name` (the field the handler actually trusts). The equality that should hold — "organization whose secret signed the request" == "organization that owns the repository being written to" — is never checked.

### Impact Explanation
An org administrator of *any* GitHub organization configured in a shared, multi-tenant Shipit deployment (a normal, unprivileged relationship with respect to other tenants' repositories) can:
1. Sign an arbitrary HTTP body with their own organization's legitimately-known `webhook_secret`, satisfying `verify_signature` (`repository.owner.login` = their own org).
2. Set `repository.full_name` inside the same signed body to `"victim-org/victim-repo"`, a repository they have no access to.
3. POST directly to `/webhooks`, bypassing GitHub entirely, causing `PushHandler`/`StatusHandler`/`CheckSuiteHandler` to run against the victim's `Stack` — triggering `GithubSyncJob`, forcing commit-status/check-suite records to be written for the victim stack, and (when `continuous_deployment` is enabled) an unauthorized deploy of the victim's stack, all without ever touching the victim repository's real webhook secret or GitHub credentials.

This satisfies the "unauthorized deploy" / cross-repository-write impact criteria: authentication is anchored to the wrong entity (the signing org) while the write target (the repository/stack) is taken from unauthenticated-by-binding data in the same payload.

### Likelihood Explanation
Any tenant admin in a multi-org Shipit installation (a documented, supported configuration — see the multi-organization example in `config/secrets.development.example.yml`) can exploit this with a single crafted HTTP request; no GitHub access, repository permissions, or session/API-client credentials for the victim are required — only the attacker's own legitimately-possessed webhook secret.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to verify the signature is the same organization that owns the repository resolved for processing — i.e., assert `repository.owner.login`/`organization.login` equals the owner segment of `repository.full_name` before dispatching to any handler, and reject the webhook otherwise.

### Proof of Concept
1. Attacker administers `attacker-org` in a Shipit instance that also tracks `victim-org/victim-repo` (different org, own `webhook_secret`).
2. Attacker builds a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<any sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully. `PushHandler#stacks` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob`/deploy actions for the victim's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
