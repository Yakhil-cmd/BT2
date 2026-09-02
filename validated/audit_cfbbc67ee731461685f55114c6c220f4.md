### Title
Webhook signature verification selects the wrong GitHub App's secret because it trusts the unauthenticated payload's `repository.owner.login` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` picks which app's `webhook_secret` to verify the HMAC against using a value read directly out of the still-unverified JSON body, while the event handlers that subsequently act on the payload resolve the target `Stack`/`Repository` using a different payload field (`repository.full_name`). This breaks the binding "the organization whose secret authenticated the request" == "the repository that is written to by the handler."

### Finding Description
`verify_signature` computes `repository_owner` from the raw, unauthenticated request body and uses it to look up which `GitHubApp` (and therefore which `webhook_secret`) should validate the signature: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github` resolves the app config via `github_app_config(organization)`, keyed by the attacker-supplied organization string: [3](#0-2) 

Crucially, `verify_webhook_signature` treats an app with no configured `webhook_secret` as always-verified: [4](#0-3) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Meanwhile, the actual action taken on the payload — resolving which `Stack`/`Repository` receives the push/status/check_suite event — is derived from a *different* field, `repository.full_name`, in `Handler#stacks`/`Handler#repository_name`: [5](#0-4) 

So the field consulted to select the verifying secret (`repository.owner.login`) is not cryptographically bound to the field that determines which repository's data gets written (`repository.full_name`). In a `Shipit.github_organizations` multi-app configuration where at least one configured organization has no `webhook_secret` set (this is an explicitly supported, documented configuration — see the "Using Multiple Github Applications" setup docs, where `webhook_secret` is optional per-organization), an unprivileged attacker can craft a payload whose `repository.owner.login` names the org without a secret (so `verify_webhook_signature` short-circuits to `true` unconditionally) while `repository.full_name` names a repository belonging to a different, secret-protected organization/stack. The signature check passes trivially and the handler still processes the forged event against the targeted stack.

### Impact Explanation
This lets an unauthenticated attacker forge GitHub webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`) for any repository/stack tracked by Shipit, as long as the deployment has at least one multi-org entry lacking a `webhook_secret`. Forged `push`/`status` events can trigger `GithubSyncJob` re-syncs and manipulate commit status records that gate continuous deployment/merge-queue decisions, and forged `membership` events can create/delete team memberships — all without possessing any organization's real webhook secret. This crosses the "organization that authenticated versus the repository that is written" trust boundary called out in the rules, and can lead to unauthorized deploy-gating state changes.

### Likelihood Explanation
Requires the operator to run Shipit with the documented multi-GitHub-App configuration (`Shipit.github_organizations`) and to have at least one org entry configured without a `webhook_secret` (explicitly optional per the setup docs). Given that is a supported, documented setup, an attacker only needs to know that such an org name exists (organization names are public) and needs zero credentials — likelihood is High whenever that configuration pattern is used.

### Recommendation
Do not let unauthenticated payload data choose which secret verifies the request. Either:
1. Verify the signature against every configured organization's secret (or against the specific org derived from routing/host configuration, not the payload) and require a match, treating "no secret configured" as "verification not possible" rather than "verification always passes"; or
2. After verification, re-derive and cross-check that the organization used to verify (`repository_owner`) matches the actual repository owner encoded in `repository.full_name` before invoking handlers, rejecting mismatches; and stop treating a blank `webhook_secret` as an automatic pass when running with a multi-app config that has other apps with secrets.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `OrgA` (no `webhook_secret` set) and `OrgB` (`webhook_secret` set), both with stacks tracked, per the multi-org secrets format shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Send `POST /github/webhooks` (or the mounted webhooks path) with:
   - `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/real-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha>"}`
   - Any/no `X-Hub-Signature` header (irrelevant since `OrgA` has no secret).
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured), so the request passes the `before_action`.
4. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/real-repo")` and enqueues `GithubSyncJob`/updates `Stack` state for the `OrgB` stack — despite the request never being signed with `OrgB`'s real webhook secret.

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
