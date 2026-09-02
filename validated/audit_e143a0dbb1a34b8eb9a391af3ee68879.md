### Title
Webhook signature verification key selection is decoupled from the repository actually acted upon, enabling cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to HMAC-verify a webhook against using `repository_owner`, taken from the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). The event handlers, however, resolve the repository/stack to act on using a *different* field of the same untrusted body: `repository.full_name` [1](#0-0) . Nothing enforces that the owner segment of `full_name` matches `repository.owner.login`/`organization.login`, so in a multi-organization Shipit deployment an attacker who legitimately administers *one* configured GitHub organization's App (and thus knows that org's `webhook_secret`) can sign a payload with their own valid secret while pointing `repository.full_name` at a different tenant's repository, causing Shipit to execute the event against a repository/stack it does not own.

### Finding Description
`Shipit::WebhooksController` verifies the HMAC signature using an app selected by `repository_owner`: [2](#0-1) 

```
repository_owner
  = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(...)
```

In a multi-org configuration each organization has its own independent `webhook_secret` set in `secrets.yml`/GitHub App settings, as documented in [3](#0-2) . Selecting the verification key by an attacker-controlled JSON field (`repository.owner.login`) is what actually determines *whose secret* is required — but it says nothing about which repository the event will be applied to.

Every handler that processes the event (`PushHandler`, `CheckSuiteHandler`, etc.) resolves the target repository purely from `repository.full_name` via `Handler#stacks`/`Handler#repository_name`: [1](#0-0) 

and `Repository.from_github_repo_name` simply splits that string and looks up the local `Repository` row — with no cross-check against `repository.owner.login` or `organization.login`: [4](#0-3) 

Because the JSON body is entirely attacker-supplied (it's an unauthenticated HTTP POST, only the raw bytes are HMAC-checked, not any internal field-consistency), an attacker can construct a payload where:
- `repository.owner.login` (or `organization.login`) = `"OrgA"` (an org the attacker legitimately administers and for which they know the configured `webhook_secret`)
- `repository.full_name` = `"OrgB/private-repo"` (a repository belonging to a different tenant organization configured on the same shared Shipit instance)

The request is signed with `OrgA`'s secret, so `verify_signature` succeeds (`Shipit.github(organization: "OrgA")` is the app whose secret matches). The handler, however, acts on `Repository.from_github_repo_name("OrgB/private-repo")`, i.e. on `OrgB`'s stacks — a repository the requester has no authorization over.

This breaks exactly the binding class called out in scope: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
Depending on the event type this enables a cross-tenant, cross-repository write while only presenting credentials of a different, unrelated organization:
- `push` → `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on `OrgB`'s stacks [5](#0-4) , forcing a git ref sync of a repository the caller has no rights to.
- `check_suite`/`status` handlers similarly operate on `OrgB`'s stacks/commits based purely on the forged `full_name`.

This is a cross-repository write triggered without any legitimate credential for the targeted repository/organization, matching the Critical impact bar ("cross-repository writes... unauthorized deploy").

### Likelihood Explanation
This requires a multi-organization Shipit deployment (as explicitly supported and documented) where the attacker is a legitimate administrator/owner of at least one of the configured GitHub organizations (and therefore knows that org's `webhook_secret`), and can direct outbound HTTP requests to the shared `/webhooks` endpoint. No Shipit session, `ApiClient` token, or private key is required — only knowledge of one tenant's own webhook secret, which that tenant's admin legitimately possesses. This is a realistic scenario for any shared/multi-tenant Shipit instance, though it does not apply to single-organization deployments (the common case), which somewhat limits overall likelihood.

### Recommendation
When resolving the target repository/stack in `Shipit::Webhooks::Handlers::Handler`, verify that the owner segment of `repository.full_name` (or the `organization.login`) matches the `repository_owner`/organization that was actually used to select the verifying `GitHubApp`/secret in `WebhooksController#verify_signature`. Reject (422) any payload where these are inconsistent, rather than trusting `full_name` unconditionally for repository lookup after verifying signature against a different attacker-chosen field.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s, per [3](#0-2) ; `OrgB` has a registered `Repository`/`Stack` the attacker does not control.
2. Attacker, who administers `OrgA`'s GitHub App and knows `OrgA`'s `webhook_secret`, crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/private-repo" }
}
```
3. Computes `X-Hub-Signature` using `OrgA`'s `webhook_secret` and `HMAC-SHA1` per `verify_webhook_signature` [6](#0-5) .
4. POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner = "OrgA"`, loads `OrgA`'s app, verifies successfully [2](#0-1) .
6. `PushHandler` resolves `stacks` from `repository.full_name = "OrgB/private-repo"` [1](#0-0)  and invokes `stack.sync_github` on `OrgB`'s stack, despite the request being authenticated only against `OrgA`'s secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
