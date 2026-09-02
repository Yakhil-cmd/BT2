### Title
Webhook signature verification is keyed on an unauthenticated `repository.owner.login`/`organization.login` field while event processing acts on a different unauthenticated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate a request's HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the *unauthenticated* raw JSON body. The event handlers that subsequently act on the request (creating jobs, updating stacks, archiving review apps, etc.) instead key off a *different* field in the same unauthenticated body, `repository.full_name`. Because both fields are attacker-controlled in the raw POST body and are never cross-checked against each other, an attacker who can produce a validly-signed payload for any one configured GitHub organization (including one whose `webhook_secret` is left blank, in which case `verify_webhook_signature` short-circuits to `true`) can point `repository.full_name` at a completely different organization's stacks.

### Finding Description
`WebhooksController#verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This chooses the `GitHubApp`/secret purely from an unverified body field. Signature verification itself can also be a no-op:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

Meanwhile, every webhook handler resolves the actual `Repository`/`Stack` to mutate from a *different* field of the same body:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 
and similarly in `PushHandler`, the `PullRequest` handlers, etc., all of which call `Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) .

The binding that should hold is: *organization whose secret validated the signature == organization owning the repository the handler acts on*. Because `repository.owner.login` (authentication key) and `repository.full_name` (the field read for authorization/target-selection) are independent JSON fields with no cross-validation, this equality is never enforced. In a multi-GitHub-App Shipit deployment (`docs/setup.md` documents this configuration, and `test/dummy/config/secrets_double_github_app.yml` shows a working example) an attacker who controls (or can trigger) a validly-signed delivery for one configured organization — or targets an organization whose `webhook_secret` is unset, which the code path explicitly supports (`return true unless webhook_secret`) — can set `repository.owner.login`/`organization.login` to that organization while setting `repository.full_name` to `other-org/other-repo`, causing the engine to accept the forged signature and then execute handler logic (queue `GithubSyncJob`, archive/unarchive review stacks, update `PullRequest` records, create `Status` records) against a Stack belonging to a wholly different, unrelated GitHub organization.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary called out in scope. Depending on the handler reached it enables unauthorized manipulation of another organization's stack state via forged, signature-accepted webhooks (e.g., forcing `push`-triggered syncs, archiving/unarchiving review stacks, injecting fabricated commit `Status`/`check_suite` results that `Stack` deploy safety checks rely upon) — i.e., cross-repository writes through a single Shipit installation, without any legitimate credential for the targeted repository/organization.

### Likelihood Explanation
Requires the deployment to configure more than one GitHub App/organization (documented, supported feature) and either (a) the attacker knowing/controlling a valid `webhook_secret` for at least one configured org, or (b) at least one configured org having no `webhook_secret` set (which the code explicitly tolerates via the `return true unless webhook_secret` bypass). Given multi-org Shipit installations are a documented, first-class configuration, and the secret-selection logic is entirely payload-driven with no secondary correlation check, this is a realistic misconfiguration-triggered path rather than a purely theoretical one.

### Recommendation
After signature verification succeeds, re-derive the organization strictly from the verified `github_app`/webhook_secret used, and require it to match the organization portion of `repository.full_name` (and `organization.login`, when present) before dispatching to any handler. Alternatively, verify the signature against every configured org's secret and only accept the match whose org equals the repository owner encoded in `full_name`, rejecting the request otherwise.

### Proof of Concept
1. Deploy Shipit configured with two GitHub Apps/orgs, e.g. `OrgA` (with `webhook_secret: secretA`) and `OrgB` (`webhook_secret:` unset/blank), per the multi-org config format in `docs/setup.md`.
2. Craft a JSON body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/private-stack-repo" },
  "ref": "refs/heads/master",
  "after": "deadbeef..."
}
```
3. POST to `/webhooks` with `X-Github-Event: push` and any `X-Hub-Signature` header (or omit it) — since `Shipit.github(organization: "OrgB")` resolves an app with a blank `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally at [5](#0-4) .
4. `PushHandler` then resolves stacks via `Repository.from_github_repo_name("OrgA/private-stack-repo")` [3](#0-2)  and enqueues `GithubSyncJob` against `OrgA`'s stack, despite the request never having been authenticated for `OrgA`.

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
