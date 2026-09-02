This confirms the finding. The binding break is fully proven: `WebhooksController#verify_signature` selects the HMAC secret using `repository_owner` (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`), while every handler (`PushHandler`, `PullRequest::OpenedHandler`, etc.) resolves the target `Stack`/`Repository` using the unrelated `repository.full_name` field via `Repository.from_github_repo_name`, with no cross-check that `repository.full_name`'s owner segment matches `repository.owner.login`.

### Title
Webhook signature is verified against `repository.owner.login`, but stack mutations are keyed on the unverified `repository.full_name` field, allowing cross-organization stack takeover - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports multiple GitHub organizations, each configured with its own `webhook_secret` in `secrets.yml`. Any attacker who administers a GitHub App installation on their own organization (a legitimate, unprivileged setup step documented in `docs/setup.md`) knows that organization's `webhook_secret` and can freely craft and sign arbitrary webhook payloads to `/webhooks`. Shipit lets the attacker choose which secret is used to validate the payload (via `repository.owner.login`), while the actual repository/stack that gets written to is selected from a completely different, unverified field (`repository.full_name`), enabling forged pushes/PR events to be attributed to any other org's stack.

### Finding Description
`WebhooksController#verify_signature` derives the signing org solely from the payload itself: [1](#0-0) [2](#0-1) 

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
```

This looks up `Shipit.github(organization: repository_owner)` and validates the HMAC using that specific organization's `webhook_secret` [3](#0-2) . Each configured org has its own independent secret [4](#0-3) , which any org owner obtains themselves when creating their GitHub App per `docs/setup.md` [5](#0-4) .

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw payload to handlers [6](#0-5) . Every handler resolves the target repository from `repository.full_name`, not `repository.owner.login`: [7](#0-6) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` splits this string on `/` and does a plain `find_by(owner:, name:)` lookup, with no relationship to the org that was used to verify the signature [8](#0-7) . `PushHandler#process` then directly calls `stack.sync_github(expected_head_sha: params.after)` on whatever stack matches that name [9](#0-8) .

The binding that should hold is: `organization authenticated by signature == owner(repository written)`. Nothing in the code enforces `params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`. An attacker who owns/administers `org-attacker` (and thus knows `webhook_secret` for `org-attacker`) can send a payload where `repository.owner.login = "org-attacker"` (so the signature validates against a secret they know) but `repository.full_name = "org-victim/some-repo"` (so the handler mutates `org-victim`'s stack).

### Impact Explanation
This crosses the "unprivileged attacker" boundary defined by the rules: no Shipit session, `ApiClient` token, or GitHub App private key is needed — only administrative control of one's own GitHub App installation, which is the documented, expected way for any organization to onboard onto a shared Shipit instance. With a forged `push` event, the attacker can trigger `Stack#sync_github` and continuous-deployment sync logic for a stack belonging to a different organization/repository that the attacker has no access to, and with crafted `pull_request` events can archive/unarchive/create review stacks for that foreign repository. This is a cross-repository write / unauthorized deploy trigger, matching the "Critical: cross-repository writes, or an unauthorized deploy" impact bucket.

### Likelihood Explanation
Likelihood is High for any Shipit deployment hosting more than one GitHub organization/tenant (a supported, documented configuration — see the multi-org `secrets.development.shopify.yml` example). Any org admin who legitimately installs their own GitHub App (a normal, unprivileged onboarding action) automatically obtains everything needed to exploit this: their own `webhook_secret` and the ability to POST to the shared `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in each `Handler`), enforce that the organization used to validate the signature matches the owner encoded in `repository.full_name` (and `organization.login` where applicable) before dispatching to handlers — e.g., reject the request if `params.dig('repository','full_name')&.split('/')&.first != repository_owner`. More robustly, resolve the target `Repository`/`Stack` first, look up the github organization tied to that `Repository` record, and verify the signature against that specific org's secret rather than trusting an attacker-controlled field to select the verification key.

### Proof of Concept
1. Shipit is configured with two orgs, e.g. `org-attacker` and `org-victim`, each with their own GitHub App and `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. Attacker administers the `org-attacker` GitHub App and therefore knows `webhook_secret` for `org-attacker`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_of_org-attacker, body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and the signature validates successfully because the attacker used the correct secret for that org.
6. `PushHandler#process` runs `Repository.from_github_repo_name("org-victim/some-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `org-victim`'s stack, even though the attacker never proved control of `org-victim`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
