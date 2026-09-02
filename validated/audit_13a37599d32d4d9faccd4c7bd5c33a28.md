### Title
Webhook signature verification is bound to `repository.owner.login`, but write actions are bound to `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The webhook signature check in `Shipit::WebhooksController#verify_signature` selects which GitHub App's secret to verify against using `repository_owner`, taken from the `repository.owner.login` (or `organization.login`) field of the *unauthenticated* JSON body [1](#0-0) . Every webhook handler, however, resolves the repository/stack to actually act on using a *different* field of the same body, `repository.full_name` [2](#0-1) . Nothing ties these two fields together, and `verify_webhook_signature` unconditionally passes whenever the organization resolved from `repository.owner.login` has no `webhook_secret` configured [3](#0-2) . This is exactly the class of bug described in the report: an authorization-relevant field (`webhook_secret` presence / the authenticated organization) exists but the code that performs the privileged action checks a different, uncorrelated field.

### Finding Description
`Shipit::WebhooksController#verify_signature` computes `repository_owner` from the raw, unauthenticated JSON payload:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

and uses it only to pick which configured `GitHubApp` (and hence which `webhook_secret`) to validate the signature against:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
``` [5](#0-4) 

`verify_webhook_signature` explicitly disables verification entirely when the resolved organization has no secret configured:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [3](#0-2) 

Once the request passes this check, `Shipit::Webhooks.for_event(event)` dispatches the **raw JSON body** to handlers, which never re-read `repository.owner.login` - they instead derive the target repository from `repository.full_name`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`PushHandler`, for example, uses this to select stacks and trigger a sync:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

`repository.owner.login` and `repository.full_name` are two independent JSON fields in the same attacker-controlled request body. On a Shipit installation that hosts multiple GitHub organizations (an explicitly documented and supported configuration - see the `github:` map keyed by org name in the setup docs and `secrets.development.shopify.yml`, where `webhook_secret` may be left `# nil`) [7](#0-6) , an attacker who knows (or guesses) that at least one configured organization has no `webhook_secret` set can:
1. Set `repository.owner.login` (or top-level `organization.login`) to that unsecured organization, causing `verify_signature` to pass unconditionally with no signature at all.
2. Set `repository.full_name` to any other organization/repository tracked by the instance (one that *does* have a properly configured secret) to have the handler act on it.

The binding that should hold is: *organization whose signature was authenticated == organization owning the repository whose stacks are mutated*. The code breaks this equality because the two checks read different, independently-controlled fields of the same unauthenticated payload.

### Impact Explanation
This allows a completely unauthenticated, unprivileged network attacker (no Shipit session, no `ApiClient` token, no `webhook_secret`, no GitHub credentials) to trigger privileged handler logic against stacks belonging to a properly-secured GitHub organization, as long as any other org configured on the same Shipit instance lacks a `webhook_secret`. Concretely this includes:
- Forcing `GithubSyncJob`/`stack.sync_github` to run against arbitrary stacks with an attacker-supplied `expected_head_sha`, which can trigger fetching and, if `continuous_deployment` is enabled on the target stack, an unauthorized deploy of new commits [6](#0-5) .
- Archiving/unarchiving review stacks or other state-changing operations exposed by other handlers (`pull_request` labeled/closed/reopened handlers) that similarly key off `repository.full_name` without any cryptographic tie to the authenticated organization [8](#0-7) .

This matches the "unauthorized deploy/rollback" and "cross-repository writes" Critical impact bucket: the deployment-trust binding between the authenticated GitHub organization and the repository actually mutated is broken.

### Likelihood Explanation
Exploitability depends entirely on whether the deployed Shipit instance has at least one configured GitHub organization without a `webhook_secret`. This is a supported, documented configuration (the setup docs and shipped example secrets files show `webhook_secret` as an optional, nullable field) [9](#0-8) [10](#0-9) . Multi-organization installations that add a new, low-value or test GitHub organization without immediately configuring a webhook secret are the most exposed. No credentials, sessions, or GitHub write access are required to attempt exploitation - only knowledge (or a guess) of which configured organization is unsecured, and the target `repository.full_name` (both discoverable via the public Shipit UI/API for unauthenticated read-configured instances or simple enumeration).

### Recommendation
- Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank; either require a secret for every configured GitHub App or treat a missing secret as `verified = false`.
- Bind the organization used for signature verification to the same field(s) used by handlers to resolve the target repository: after verifying, re-derive `repository_owner` from `repository.full_name`'s owner segment (or vice versa) and reject the request (422) if they disagree.
- Consider having handlers independently confirm that the resolved `Repository#owner` matches the GitHub organization whose secret validated the request, rather than trusting `repository.full_name` unconditionally.

### Proof of Concept
Given a Shipit instance configured with two organizations, `unsecured-org` (no `webhook_secret`) and `victim-org` (properly configured with a secret, owning tracked stacks):

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/protected-repo"
  }
}
```

No `X-Hub-Signature` header is required: `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank [11](#0-10) . The request then reaches `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("victim-org/protected-repo")` [2](#0-1)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on `victim-org`'s stacks [6](#0-5) , entirely bypassing the organization-level authentication intended by the webhook signature scheme.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
