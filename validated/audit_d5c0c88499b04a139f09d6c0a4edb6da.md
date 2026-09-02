### Title
Signature verification keyed on attacker-controlled `repository.owner.login` allows forged webhooks to trigger deploy syncs for a repository belonging to a different organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit setups (`secrets.github` keyed by org, see `lib/shipit.rb`), the webhook signature check selects **which** org's `webhook_secret` to validate against using a field read straight out of the unauthenticated JSON body, while the handler that actually acts on the webhook resolves the target repository/stack from a *different* field of that same untrusted body. These two fields are never bound together by the signature.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to check the signature against like this: [1](#0-0) 

`repository_owner` is derived purely from the JSON payload, with no cryptographic binding at this point: [2](#0-1) 

`Shipit.github(organization:)` resolves the app config (and `webhook_secret`) for whatever organization name is supplied: [3](#0-2) 

If that org's `webhook_secret` is unset (a supported, documented configuration — see `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml` where multiple orgs may each have `webhook_secret: # nil`), verification always succeeds: [4](#0-3) 

After this "verification" step, `create` re-parses the *same* attacker-controlled raw body and dispatches it to handlers unconditionally: [5](#0-4) 

Handlers (e.g. `PushHandler`) resolve the actual target stack/repository from a **separate** field of the same payload — `repository.full_name` — which is never cross-checked against `repository_owner`: [6](#0-5) [7](#0-6) 

The broken binding: `organization authenticated (repository_owner, used to select the signing secret) == organization/repository written to (repository.full_name, used by PushHandler/Repository.from_github_repo_name to enqueue `stack.sync_github`)`. An attacker who knows (or who runs) an organization in the same Shipit deployment whose GitHub App has no `webhook_secret` configured (or an app for an org they legitimately control) can craft a webhook body where `repository.owner.login`/`organization.login` names that low/no-secret org (so `verify_signature` passes trivially) while `repository.full_name` names a *different* repository/stack actually configured in Shipit under another organization. The forged event is then processed and can trigger `stack.sync_github(expected_head_sha: ...)`, `RefreshCheckRunsJob`, membership/team writes (`MembershipHandler`), or PR-state handlers against that unrelated stack — all without possessing that org's real webhook secret.

### Impact Explanation
This crosses a repository-trust boundary purely through payload manipulation: an unprivileged party can make Shipit believe a push/status/check_suite/membership event legitimately originates from a repository/org it does not control, causing Shipit to act (sync commits, refresh CI check state feeding deploy safety gates, or mutate `Team`/`Membership` records used for `Shipit.github_teams` authorization) on a target it wasn't authorized to influence. This is a cross-repository write / authorization-escalation vector, matching the High/Critical categories (`Shipit.github_teams` escalation, unauthorized state mutation) called out in scope. Severity depends on operator configuration (multiple orgs configured, at least one without a real `webhook_secret`), which is an explicitly documented and supported configuration.

### Likelihood Explanation
Requires: (1) a Shipit instance configured for multiple GitHub organizations (documented, supported feature in `docs/setup.md`), and (2) at least one configured organization app with no `webhook_secret` set, or knowledge of one org's secret. Given `webhook_secret` is optional per the config schema and examples ship with it commented out/nil, this is plausible in real deployments, especially incrementally-configured multi-org installs. No session, API token, or GitHub write access is required — only the ability to POST to the public `/webhooks` endpoint, which is unauthenticated by design.

### Recommendation
Bind the field used to select the verifying secret to the field the handlers actually act on: verify the signature using the organization/owner implied by `repository.full_name` (the same value `Handler#repository_name` uses), not a separately-dug `repository.owner.login`/`organization.login`. Alternatively, after signature verification, re-derive `repository_owner` from the verified payload and assert it matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request if they diverge. Also consider requiring `webhook_secret` to be present for every configured organization (fail closed) rather than defaulting to `true` when absent.

### Proof of Concept
Given a Shipit instance configured with two orgs in `secrets.github`:
```yaml
github:
  low_security_org:
    webhook_secret: # nil — signature check is a no-op
  target_org:
    webhook_secret: <real-secret>
```
An attacker with no credentials sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "repository": { "owner": { "login": "low_security_org" }, "full_name": "target_org/some-tracked-repo" },
  "organization": { "login": "low_security_org" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
`verify_signature` calls `Shipit.github(organization: "low_security_org")`, whose `verify_webhook_signature` returns `true` unconditionally (no `webhook_secret`), so the request passes with `head(422)` never triggered. `create` then dispatches the full payload to `PushHandler`, which resolves `Repository.from_github_repo_name("target_org/some-tracked-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack belonging to `target_org`, whose real webhook secret the attacker never had to know.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
