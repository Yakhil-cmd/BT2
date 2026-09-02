Confirmed root cause: `Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the request against using `repository_owner`, which is read directly from the unauthenticated JSON body, not from anything covered by the signature check's own trust boundary. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook signature verification org is selected from an unverified payload field, allowing signature-check bypass in multi-org installs - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the `GithubApp`/`webhook_secret` used to validate `X-Hub-Signature` based on `repository_owner`, a value taken straight out of the untrusted request body (`params.dig('repository', 'owner', 'login')`), before the signature has been validated. In `verify_webhook_signature`, if the selected org's config has no `webhook_secret` set, the method unconditionally returns `true`. Because the org used for verification is attacker-chosen (it's just JSON in the POST body), an attacker can send a forged webhook whose `repository.owner.login` names any org configured in `secrets.github` that lacks a `webhook_secret`, causing the signature check to pass trivially — even though the event handlers afterward may act on a completely different `repository` (any stack in the datastore, since handler lookups match by repo full name/branch from the same attacker-controlled payload).

### Finding Description
The binding that should hold is: **the GitHub organization used to verify a webhook's signature == the GitHub organization that actually produced/signed that webhook**. Instead the code implements: **the GitHub organization used to verify == whatever organization login string appears, unauthenticated, in the JSON body**.

- `repository_owner` is derived from the JSON payload before any authentication: [2](#0-1) 
- That value is used to fetch a `Shipit.github(organization: repository_owner)` app config and verify the signature against it: [4](#0-3) 
- `verify_webhook_signature` short-circuits to `true` when the selected org has no `webhook_secret` configured: [3](#0-2) 
- Multiple orgs can be configured simultaneously via `secrets.github`, each with independent `webhook_secret` (some possibly blank/unset, e.g. staging/test orgs), as shown by the multi-org lookup helpers: [5](#0-4) 
- After "verification," the raw `params` (fully attacker-controlled, including the actual target `repository.full_name`/branch used by handlers such as `PushHandler`) are dispatched to handlers regardless of which org was used to pass the signature check: [6](#0-5) [7](#0-6) 

Before the attacker's request: signature verification is meant to bind the payload to the org whose secret produced `X-Hub-Signature`. After the attacker's request: the attacker supplies `repository.owner.login = "<org-without-secret>"` for the *verification* lookup while supplying `repository.full_name` / `ref` for a *different, real* stack for the handler dispatch — the two fields are never cross-checked, and the org used to authorize the request has no cryptographic relationship to the org whose stack is actually mutated.

### Impact Explanation
If any configured GitHub App entry in `secrets.github` (e.g., a legacy/staging config, or one where `webhook_secret` was left blank per the documented config format) lacks a `webhook_secret`, an unauthenticated network attacker can forge arbitrary webhook events (`push`, `status`, `membership`, `pull_request`, `check_suite`, etc.) for any stack tracked by the instance, not just stacks under the unsecured org. This can trigger unauthorized `GithubSyncJob`/deploy-eligible state changes, fabricate commit statuses, or add/remove team memberships — all without possessing any GitHub webhook secret, `ApiClient` token, or session. This satisfies the Critical/High bar of "authentication bypass" for the webhook trust boundary and can cascade into unauthorized deploy/merge-queue state changes for arbitrary repositories tracked by the instance.

### Likelihood Explanation
Requires the operator to run Shipit with the multi-org GitHub App configuration format and to have at least one configured org without a `webhook_secret` (the single-app legacy schema is unaffected since it has one implicit config). This is a plausible real-world misconfiguration (e.g., a test/dummy org left blank, as seen in the repo's own test fixtures where `webhook_secret: null`) rather than a purely theoretical setup. [8](#0-7) 

### Recommendation
Do not select the verification org from unauthenticated payload data. Instead:
- Verify the signature against every configured org's secret (or the specific org tied to the target stack/repository already resolved from the DB) and reject if none match, rather than trusting `repository_owner` from the body to pick the org.
- Alternatively, resolve the target `Stack`/`Repository` from persisted, trusted data first, and require its owning org's secret to validate the signature — never let the payload dictate its own verifier.
- Treat a missing `webhook_secret` for any org as a hard misconfiguration (raise/alert) rather than silently passing verification.

### Proof of Concept
1. Configure `secrets.github` with two orgs: `OrgA` (has `webhook_secret: real-secret`, owns tracked stacks) and `OrgB` (has `webhook_secret: nil`, e.g. an old/staging entry).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/real-stack-repo" }
}
```
No `X-Hub-Signature` header is required to be correct — `repository_owner` resolves to `OrgB`, `Shipit.github(organization: 'OrgB').verify_webhook_signature` returns `true` immediately because `OrgB`'s `webhook_secret` is blank.
3. `verify_signature` passes, `create` runs, and `PushHandler` looks up stacks by `branch`/repository derived from the same forged payload — which can reference `OrgA/real-stack-repo`, a stack under the securely-configured org — dispatching a forged `GithubSyncJob` for it.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
