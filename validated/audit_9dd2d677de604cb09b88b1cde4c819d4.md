### Title
Cross-Organization Webhook Forgery via Signature/Target Mismatch in Multi-Org Configuration - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When Shipit is configured with multiple GitHub organizations (a documented, supported configuration), the webhook signature verification is keyed to a different field than the one used to select which repository/stack the webhook payload actually mutates. This lets an attacker who legitimately controls the webhook secret for one configured organization forge events that write into another configured organization's stacks.

### Finding Description
`WebhooksController#verify_signature` selects which `GithubApp`/webhook secret to validate against based on `repository_owner`, which is read from the payload's `repository.owner.login` (or `organization.login` fallback): [1](#0-0) [2](#0-1) 

The signature itself is only an HMAC over the raw payload bytes using that organization's `webhook_secret`, with no binding to any single "repository" value inside the payload: [3](#0-2) 

Once verification passes, the actual event handlers resolve the target repository/stack from a *different* payload field — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [4](#0-3) 

`PushHandler` uses this to enqueue a GitHub sync (`stack.sync_github`) for whatever stacks match `full_name`: [5](#0-4) 

`StatusHandler` writes a commit CI status keyed only by `sha` (no repository/org check at all), and `CheckSuiteHandler` schedules check-run refreshes for stacks matched by branch/sha, again independent of the field used for signature verification: [6](#0-5) [7](#0-6) 

Shipit explicitly supports hosting multiple, independently-configured GitHub organizations/apps, each with its own `webhook_secret`, in a single install: [8](#0-7) [9](#0-8) 

**The broken binding:** `repository_owner` (used to select and verify the signing organization) ≠ `repository.full_name` (used to select the repository/stack that is actually written to). Verifying "this webhook came from organization X" does not verify "this webhook is about a repository owned by organization X." An attacker who is a legitimate administrator of the GitHub App/webhook for OrgA (and thus knows or controls OrgA's `webhook_secret`, e.g. by re-pointing OrgA's GitHub webhook delivery, or via a compromised/rotated secret they have configuration access to) can craft a POST to `/webhooks` where:
- `repository.owner.login` = `"OrgA"` (or `organization.login` = `"OrgA"`) — satisfies `verify_signature`, which resolves `Shipit.github(organization: "OrgA")` and validates the HMAC with OrgA's secret.
- `repository.full_name` = `"OrgB/some-repo"` — a stack belonging to a completely different organization also configured on the same Shipit instance.

Because the HMAC covers the raw bytes and both fields are attacker-controlled inside that signed payload, the attacker can produce a validly-signed body for OrgA while targeting OrgB's stack.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary. Concretely, an attacker with only OrgA-level webhook control can, without ever touching OrgB's secret:
- Force a `push` event that triggers `GithubSyncJob`/`sync_github` for an OrgB stack with an attacker-chosen `expected_head_sha`, since `stacks` resolution is keyed by `repository.full_name`, not by the verified `repository_owner`.
- Forge `status` events, which are matched purely by commit `sha` with no repository-ownership check at all (`Commit.where(sha: params.sha)`), letting the attacker write a fake `success` CI status on a commit belonging to another org's stack. Since deployability gating elsewhere depends on green CI status, this can influence whether a commit is eligible for deploy/merge in a repository the attacker has no legitimate access to.
- Forge `check_suite` events that schedule check-run refreshes against OrgB's stacks.

This is a cross-repository/cross-organization write achieved by exploiting a payload field that is never covered by the signature-selection logic, matching the "unauthorized deploy/merge or cross-repository writes" High/Critical impact bar in the rules.

### Likelihood Explanation
Exploitation requires the attacker to already control (or be able to forge signatures for) at least one of the multiple GitHub organizations configured on a shared Shipit instance — a realistic scenario for a platform team hosting several business units/orgs on one Shipit deployment, where each org's admins manage their own GitHub App/webhook secret independently but share the Shipit application and database of stacks. Any such org-scoped webhook admin is an "unprivileged attacker" with respect to every other org's stacks, satisfying the analog's bar. Single-org installations (`github_default_organization` nil, one org configured) are not exploitable since there is only one possible target.

### Recommendation
Bind webhook signature verification to the same repository/organization identity that handlers use to select their target. Concretely, after verifying the signature for `repository_owner`, re-derive the organization from `repository.full_name` (or `Repository.from_github_repo_name`) and reject the event (422) if it does not match the organization whose secret validated the signature. Alternatively, verify the signature using the secret associated with the *resolved target repository's* owner rather than the owner field taken at face value from the payload before any cross-check.

### Proof of Concept
1. Configure Shipit in multi-org mode with `OrgA` and `OrgB`, each with distinct `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. As an attacker who administers OrgA's GitHub App/webhook (and thus its `webhook_secret`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker_chosen_sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and set `X-Github-Event: push`.
4. POST to `/webhooks`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` from `repository.owner.login` and the signature validates successfully.
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("OrgB/target-repo")`, enqueuing `stack.sync_github(expected_head_sha: "<attacker_chosen_sha>")` for a stack the attacker has no legitimate access to — despite having authenticated only as OrgA.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
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
