### Title
Webhook signature verification keyed on `repository.owner.login`/`organization.login` while every handler resolves the target repository from the independent `repository.full_name` field — cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub App/organization secret to validate the inbound webhook against using one JSON field (`repository.owner.login`, falling back to `organization.login`), while every registered webhook handler (`PushHandler`, the `PullRequest::*` handlers, etc.) resolves the actual `Stack`/`Repository` to mutate using a **different**, independently-controlled JSON field: `repository.full_name` [1](#0-0) . Nothing in the code enforces that `repository.owner.login` and `repository.full_name` refer to the same repository/org. Combined with the fact that `GitHubApp#verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as automatically valid, an attacker who can reach the public `/webhooks` endpoint can forge a payload that authenticates under an organization with no configured `webhook_secret` while acting on a completely different, unrelated repository's stack.

### Finding Description
`verify_signature` selects the signing app/secret via a field the attacker fully controls in an unauthenticated POST body:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when the resolved org's `webhook_secret` is blank:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Shipit explicitly supports multi-organization configuration where each org has its own independent `webhook_secret`, and the documentation/example configs show `webhook_secret` as optional/nil by default: [4](#0-3) [5](#0-4) 

After signature "verification" passes, `WebhooksController#create` dispatches the raw parsed JSON to handlers unmodified:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [6](#0-5) 

Every handler's `Handler#repository_name` (and duplicated logic in the pull-request handlers) resolves the target `Repository`/`Stack` from `repository.full_name` — a field entirely disconnected from `repository_owner` used at the verification stage:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`PushHandler` then forces a sync to an attacker-supplied SHA on any stack matching that `full_name`/branch:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [7](#0-6) 

**Binding broken:** *the organization whose secret authenticated the request* ≠ *the repository/organization whose stack the handler writes to*. `verify_signature`'s `repository_owner` (org A, chosen by the attacker to be an org with no configured `webhook_secret`) is never required to equal `repository.full_name`'s owner (org B, any real tracked repository). Since `Shipit.github(organization:).verify_webhook_signature` auto-passes when `webhook_secret` is blank for org A, the entire raw body — including the `repository.full_name` pointing at org B — sails through unauthenticated.

### Impact Explanation
An unauthenticated, unprivileged network attacker (no Shipit session, no `ApiClient` token, no `webhook_secret` knowledge) who can reach `POST /webhooks` can:
- Force `stack.sync_github(expected_head_sha: <attacker sha>)` on any tracked stack of any organization, as long as one configured org in `Shipit.github_organizations` has a blank `webhook_secret` (explicitly the default/example configuration shown for every listed org in `docs/setup.md` and `config/secrets.development.*.yml`).
- Trigger `PullRequest::*` handlers (`ClosedHandler`, `LabeledHandler`, `AssignedHandler`, etc.) to alter PR/review-stack state (archive/unarchive review stacks, mutate `github_pull_request` cached state) for a repository outside the org the attacker actually controls.

This is a cross-organization/cross-repository write via a spoofed, unauthenticated webhook — matching the "Critical: cross-repository writes / unauthorized deploy" impact bucket, since forcing `sync_github` to an attacker-chosen SHA on the target branch influences what commit is treated as deployable/deployed.

### Likelihood Explanation
Likelihood is contingent on operational configuration: the vulnerability only manifests when Shipit is configured with multiple GitHub organizations (the documented multi-org schema) and at least one configured organization has no `webhook_secret` set. This is exactly the default/example state shown in the shipped example config files (`webhook_secret: # nil`) and is not flagged anywhere as unsafe, making the misconfiguration plausible in real deployments. No credentials, sessions, or tokens are required by the attacker; only the existence of a public `/webhooks` route (always mounted per `config/routes.rb`) and the described org-secret gap. `repository.owner.login` vs `repository.full_name` decoupling is unconditional and requires no special setup.

### Recommendation
- Reject webhooks where `repository.owner.login` (or `organization.login`) does not match the owner segment of `repository.full_name`.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-organization configurations; require an explicit opt-in (e.g., a distinct `insecure_skip_signature!` flag) or fail closed.
- Select the signing secret/org strictly from the resolved `Repository`/`Stack` looked up via `repository.full_name`, not from an attacker-supplied `owner.login`/`organization.login` field, and verify that lookup before doing anything with the payload.

### Proof of Concept
Given a Shipit deployment configured with two orgs, e.g. as in `test/dummy/config/secrets_double_github_app.yml`-style config, where `OrgA` has `webhook_secret: nil` and `OrgB` (real, tracked in Shipit) has stacks tracking `OrgB/real-repo`:

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json
(no X-Hub-Signature needed — OrgA has no secret)

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/real-repo"
  }
}
```

- `repository_owner` resolves to `"OrgA"`.
- `Shipit.github(organization: "OrgA").verify_webhook_signature(...)` returns `true` unconditionally because `OrgA`'s `webhook_secret` is blank [3](#0-2) .
- Request passes `verify_signature`; `PushHandler` runs, resolves `Repository.from_github_repo_name("OrgB/real-repo")` [1](#0-0) , and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the real `OrgB` stack tracked by Shipit — despite the attacker never possessing `OrgB`'s webhook secret, GitHub App credentials, or any Shipit session/token.

**Uncertainty:** I could not fully trace `Stack#sync_github`'s downstream effects (e.g., whether it can directly trigger a deploy of the forced SHA or merely updates cached commit/status metadata) within the tool budget available; a full session with terminal/file access would be needed to confirm the exact downstream blast radius (e.g., whether `ci.require`/merge-queue safety checks could still be bypassed once the wrong SHA is marked as head). The core authentication/authorization flaw (org selected for signature ≠ org/repo acted upon; blank-secret-passes) is confirmed directly from the source.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
