## Confirmed vulnerability found

### Title
Webhook signature verification keyed by attacker-controlled `repository.owner.login` allows cross-organization webhook forgery in multi-tenant GitHub App setups - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments (`Shipit.github_organizations` / `secrets.github` keyed by org name), `WebhooksController#verify_signature` selects *which* GitHub App config (and thus which `webhook_secret`) to verify the incoming HMAC signature against based on `repository_owner`, a value read directly from the unverified JSON body. The handler that later acts on the payload (e.g. `PushHandler`) resolves the target `Repository`/`Stack` using a *different* field from the same unverified body: `repository.full_name`. Because the field used to pick the verification secret is not cryptographically bound to the field used to pick the affected repository, an attacker who knows (or controls) the webhook secret for *any one* onboarded GitHub organization can forge a signature that passes verification while making the payload's `repository.full_name` point at a stack belonging to a *different* organization.

### Finding Description
`verify_signature` picks the app/secret using attacker-supplied data before any authentication has occurred: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
``` [2](#0-1) 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` maps the organization name to a per-org config/secret in the multi-org schema: [3](#0-2) 

Once the request is accepted (`head(:ok)` not raised), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked, and handlers such as `PushHandler` resolve the target stacks using `repository.full_name` from the *same untrusted body*: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` further splits `owner/name` straight out of this field with no cross-check against `repository.owner.login`: [6](#0-5) 

The equality that should hold is:
`organization whose secret authenticated the request == organization that owns the repository/stack being mutated by the handler`

Before the fix (still true in this codebase), these two are read from independent, attacker-controlled JSON keys (`repository.owner.login` vs `repository.full_name`) inside the same unauthenticated payload, so the equality is not enforced — an attacker can set `repository.owner.login = "org-with-known-secret"` while setting `repository.full_name = "victim-org/victim-repo"`.

### Impact Explanation
If a Shipit instance is configured with multiple GitHub organizations (`docs/setup.md` "Using Multiple GitHub Applications" / `test/dummy/config/secrets_double_github_app.yml`), and any one org's `webhook_secret` is known to an attacker (e.g. a weak/leaked secret for a low-value org, or an org where `webhook_secret` was left blank as shown in the example configs, which causes `verify_webhook_signature` to `return true unless webhook_secret`), the attacker can send arbitrary forged webhook events (`push`, `status`, `check_suite`, `membership`, etc.) that are treated as authentic for a *different, victim organization's* repositories/stacks. This can trigger unauthorized `GithubSyncJob`s, fake commit statuses, membership/team changes, or otherwise manipulate deploy state for repositories the attacker has no legitimate access to — an authorization boundary crossing consistent with the "High: escalation... unauthenticated read/write of stack state" impact class, and depending on downstream handler trust of injected commit/status data, could contribute to an unauthorized deploy.

### Likelihood Explanation
Exploitability requires: (1) a multi-organization Shipit deployment, and (2) knowledge of at least one configured org's webhook secret (or an org configured with no secret, which the code explicitly supports and treats as "always verified": `return true unless webhook_secret`). Given that `docs/setup.md` explicitly documents the blank/optional secret as a supported configuration, and that organizations may have differing security postures for who can see their secret, this is a realistic condition in real Shipit fleets that mix trusted/less-trusted organizations behind one instance.

### Recommendation
Do not select the verification key from the same untrusted payload that determines which repository/stack is mutated. Instead:
1. Verify the signature against every configured organization's secret (or use a signature transport that identifies the app unambiguously, e.g. a distinct URL/path per org) rather than trusting `repository.owner.login`.
2. After verification succeeds, additionally assert that the organization whose secret matched is the same organization referenced by `repository.full_name` (and `organization.login`) before dispatching to handlers.
3. Treat a blank/absent `webhook_secret` for any organization as a misconfiguration warning rather than an automatic pass, or require explicit opt-in for unsigned orgs.

### Proof of Concept
Given a Shipit instance configured with two organizations, `org-a` (attacker knows `webhook_secret_a`) and `org-b` (victim), an attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC(webhook_secret_a, body)>
Body:
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
`verify_signature` calls `Shipit.github(organization: "org-a")` and validates using `webhook_secret_a`, which succeeds since the attacker crafted the signature with that secret. The request passes, and `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, dispatching a `GithubSyncJob` against `org-b`'s stack — even though the signature only proves knowledge of `org-a`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-35)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
