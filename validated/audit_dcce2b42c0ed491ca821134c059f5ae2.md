### Title
Webhook status ingestion is unscoped by repository, breaking the "authenticated organization" ↔ "repository written" binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
This is the direct structural analog of the `Govshuttle` finding: a message type is processed by a handler that never checks the binding the signature/authorization was supposed to establish. In `Govshuttle`, `MsgLendingMarketProposal`/`MsgTreasuryProposal` were defined but never routed through a verified message server. In Shipit, the GitHub webhook `status` event is routed through `Shipit::Webhooks::Handlers::StatusHandler`, which writes a `CommitStatus` to the database using only the payload's `sha`, with **no check that the commit belongs to a repository owned by the GitHub organization whose webhook signature was actually verified**.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC against using `repository_owner`, a value read straight out of the untrusted, attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

In a multi-organization deployment, each organization has its own `webhook_secret`, selected via `Shipit.github(organization: repository_owner)`: [3](#0-2) [4](#0-3) 

All *other* handlers correctly bind the write target to the same organization/repository the payload claims, by resolving `stacks` from `payload.dig('repository', 'full_name')` via the shared `Handler` base class: [5](#0-4) [6](#0-5) 

`StatusHandler`, however, never calls `stacks`/`repository_name` at all — it looks up commits **globally by `sha`** across the entire Shipit installation and writes a status to whatever commit matches, regardless of which repository or organization it belongs to: [7](#0-6) 

So the equality the system is supposed to guarantee — `organization whose secret verified the signature == organization owning the repository being written to` — is never checked for `status` events. `verify_signature` only proves "this request knows Org A's webhook secret"; `StatusHandler` then writes state for *any* commit sha in the database, belonging to *any* stack/org.

### Impact Explanation
An attacker who controls (or is an authorized member of) any single GitHub organization/repository connected to this Shipit instance — i.e., someone who can legitimately trigger real `status` webhook deliveries for their own, unrelated org (this is not a privileged Shipit account, GitHub App private key, or Shipit API token) — can forge a `status` payload whose `sha` matches a real commit belonging to a completely different organization's stack. Because `StatusHandler` performs no repository/organization scoping, this injects a fabricated `CommitStatus` (e.g. a fake `"success"` state for a CI context) onto a commit they have no access to. Since commit statuses feed into `Shipit::CommitChecks`/`Status::Group` which stacks use to decide whether a commit is safe to deploy or merge, this is a cross-repository, cross-tenant write with the potential to falsify CI results and unblock/trigger deploys on repositories the attacker does not own — matching the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires only the ability to deliver one correctly-signed `status` webhook for *any* organization configured in the Shipit instance (no Shipit session, API token, or GitHub App private key needed for the *target* org) and knowledge of a `sha` value present on the target stack (commit SHAs are not secret — they're visible on GitHub, in PRs, CI logs, etc.). This is straightforward to exploit in any multi-organization Shipit deployment.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already do so) to commits belonging to a repository resolved from the payload's `repository.full_name`/owner, exactly like `PushHandler` and the `PullRequest` handlers do via `Handler#stacks`/`#repository_name`. Additionally, verify that `repository_owner` used to select the verifying `webhook_secret` matches the organization portion of `repository.full_name` in the same payload, so the two can never diverge.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple GitHub Applications").
2. Attacker legitimately administers a repo in `OrgA` and can trigger/replay a validly HMAC-signed webhook delivery for `OrgA` (`X-Hub-Signature` computed with `OrgA`'s `webhook_secret`).
3. Attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<valid signature for OrgA's secret>
{
  "sha": "<real commit sha belonging to a stack in OrgB>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, validates against `OrgA`'s secret, succeeds — [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the `OrgB` commit (unrelated to the verified `OrgA` signature), and calls `create_status_from_github!`, writing a forged passing status for `OrgB`'s commit — [7](#0-6) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
