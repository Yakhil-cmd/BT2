### Title
Webhook signature verified against a self-reported organization while all handlers act on a self-reported repository, allowing cross-organization webhook forgery in multi-app deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against based on `repository_owner`, a value pulled straight out of the attacker-controlled JSON body, while every webhook handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) selects the `Stack`/`Repository` to act on using `repository.full_name`, also pulled from the same untrusted body. Nothing binds these two fields to each other cryptographically, so in a Shipit instance configured with per-organization GitHub Apps (`Shipit.github_organizations`), a party who legitimately controls the webhook secret for *one* organization can forge a valid signature for a payload that claims to originate from that organization while pointing all the actual repository-mutating fields at a stack belonging to a *different* organization.

### Finding Description
Signature verification and secret selection: [1](#0-0) [2](#0-1) 

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
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up the app configuration (and thus the `webhook_secret`) keyed by whatever organization name appears in `repository_owner`: [3](#0-2) 

The actual repository/stack that gets mutated by a handler is resolved independently, from `repository.full_name` in the very same request body: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on whatever stack `repository_name` resolves to: [5](#0-4) 

Because `repository_owner` (used for **signature verification/secret selection**) and `repository.full_name` (used for **which repository's stacks are written to**) are two independently attacker-supplied fields of the same unsigned-at-parse-time JSON body, an attacker who legitimately possesses (or has been issued) a valid `webhook_secret` for *one* organization onboarded to a multi-org Shipit instance can:
1. Set `organization.login` (or `repository.owner.login`) to their own organization, so `verify_signature` fetches and validates against their own known secret — the HMAC check passes because they compute it correctly with their own secret over the full raw body.
2. Set `repository.full_name` to `victim-org/victim-repo`, an entirely different organization's repository that is registered as a Shipit `Repository`/`Stack`.

The equality the app implicitly (and incorrectly) assumes is:
`organization authenticated by verify_signature == organization owning the repository acted upon by handlers`

This equality does not hold because both sides are read from the same unauthenticated payload, and no code cross-checks that `repository.full_name`'s owner matches `repository_owner`.

### Impact Explanation
This breaks a genuine authentication boundary between GitHub organizations hosted on the same Shipit instance. Concretely, with a spoofed `push` payload, the attacker can trigger `Stack#sync_github(expected_head_sha:)` on a stack belonging to a different organization, which can drive Shipit's understanding of the last known commit/ref for that repository and, depending on stack configuration (continuous delivery, undeployed commit tracking), lead to deploys being kicked off against attacker-influenced SHAs, or Shipit's `status`/`check_suite` handlers being manipulated to mark victim-org commits green even though they never ran through victim-org's actual CI — a path to an unauthorized deploy. This lands squarely in the "authorization bypass across an organizational boundary that authorizes an unintended deploy" category (Critical/High per the rules), since the trust boundary crossed is exactly "organization that authenticated versus the repository that is written."

### Likelihood Explanation
Exploitability is gated on the deployment running the *multi-organization* GitHub App configuration (`secrets.github` keyed by multiple org names, i.e., `Shipit.github_default_organization` non-nil) and the attacker already possessing a valid webhook secret for at least one onboarded organization (their own, if Shipit is offered as a shared/multi-tenant service, or a leaked/lower-trust org's secret). This is a supported, documented configuration shape (`Shipit.github_organizations`, `github_app_config`) rather than a hypothetical one, so likelihood is credible in any shared Shipit deployment, though not in the common single-organization/single-secret installation (where `repository_owner` is irrelevant and the same secret is used regardless).

### Recommendation
Do not select the verification secret from an attacker-controlled field independent of the field used for repository resolution. Verify the signature using the secret associated with the **actual target repository's** known owner (looked up from the already-registered `Repository`/`Stack` record, not from the JSON body), or, at minimum, cross-check that `repository.owner.login` (used for secret selection) matches the owner segment of `repository.full_name` (used for repository resolution) before dispatching to any handler, rejecting the webhook if they diverge.

### Proof of Concept
Given a Shipit instance configured with multiple GitHub Apps/orgs (`attacker-org` and `victim-org`), where the attacker knows `attacker-org`'s `webhook_secret`:

```ruby
payload = {
  "ref" => "refs/heads/main",
  "after" => "deadbeefattackerchosen",
  "repository" => { "full_name" => "victim-org/victim-repo", "owner" => nil },
  "organization" => { "login" => "attacker-org" }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", ATTACKER_ORG_WEBHOOK_SECRET, payload)

post "/webhooks",
  body: payload,
  headers: { "X-Github-Event" => "push", "X-Hub-Signature" => signature }
```

`repository_owner` resolves to `"attacker-org"` (via the `organization.login` fallback since `repository.owner` is nil), so `verify_signature` validates successfully against the attacker's own known secret. `PushHandler#process`, however, resolves `repository_name` to `"victim-org/victim-repo"` and calls `sync_github(expected_head_sha: "deadbeefattackerchosen")` on victim-org's stack — a repository the attacker has no legitimate webhook credentials for.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
