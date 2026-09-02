### Title
Cross-repository commit status forgery via unscoped `StatusHandler` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit supports hosting multiple GitHub Apps for multiple GitHub organizations [1](#0-0) . Each webhook request is authenticated by looking up the app config for the organization named in the payload's `repository.owner.login` (or `organization.login`) field and validating the HMAC signature against that specific organization's `webhook_secret` [2](#0-1) [3](#0-2) . This establishes an authentication binding of "organization whose secret signed this payload" ⇒ "repository the payload claims to describe." However, the `status` event handler never re-checks that binding: it looks up commits purely by `sha`, globally, with no repository/organization scoping at all.

### Finding Description
`Shipit::Webhooks::Handlers::Handler` (the base class used by every webhook handler) exposes a `stacks` helper that scopes lookups to the repository named in the payload via `Repository.from_github_repo_name(repository_name)` [4](#0-3) . Handlers such as `PushHandler` and `CheckSuiteHandler` correctly use this scoped `stacks` relation before acting on payload data [5](#0-4) .

`StatusHandler`, however, bypasses this scoping entirely:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

The signature-verification step in `WebhooksController#verify_signature` only proves that *some* organization's GitHub App secret signed the payload — it derives that organization strictly from `repository.owner.login`/`organization.login` in the payload body, values fully controlled by whoever owns that installation [3](#0-2) . Nothing ties the verified organization to the `sha` field that `StatusHandler` actually acts on. Because `Commit.where(sha:)` matches any commit row in the entire Shipit instance sharing that SHA — regardless of which repository/stack it belongs to — an attacker who owns a GitHub App installation for **any** onboarded organization (e.g., their own low-privilege org/repo configured in `secrets.yml`, as shown by the multi-org fixture `secrets_double_github_app.yml` [7](#0-6) ) can send a validly-signed `status` webhook whose `sha`/`state`/`context` describe a commit belonging to a *different* organization's stack.

This is the same class of bug as the report: the entity that was cryptographically authenticated (organization A, via its webhook secret) is not the entity actually written to (commit/stack belonging to organization B), because the write path (`Commit.where(sha:)`) ignores the repository scoping that the authentication step implicitly assumed.

### Impact Explanation
Commit statuses created this way feed directly into deploy-gating logic: `Stack`/`DeploySpec` `ci.require` configuration and `CommitChecks` consult a commit's `Status` records to decide whether CI requirements are satisfied before allowing a deploy [8](#0-7) [9](#0-8) . An attacker controlling any one onboarded GitHub App installation can forge a "success" status for a commit SHA in a victim organization's repository they do not control — satisfying `ci.require` and enabling an unauthorized deploy, or conversely forge a "failure"/"error" status to block legitimate deploys (denial of deploy) in a victim stack. This is a cross-repository write of security-relevant state (commit CI status) crossing an organizational trust boundary that the webhook signature was supposed to enforce.

### Likelihood Explanation
Requires the operator to run Shipit with more than one onboarded GitHub organization/App (a documented, supported configuration [1](#0-0) ), and requires the attacker to know/guess a target commit SHA — which is public information for any commit that exists in a public repository or is otherwise known to the attacker (e.g., via the PR/commit that they are trying to bypass CI for). No repository write access, Shipit session, or API token is needed — only control of one legitimately configured GitHub App installation elsewhere in the same Shipit deployment.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup through the same `stacks`/`repository_name` binding used by every other handler (e.g., `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent), ensuring the commit acted upon actually belongs to the repository named in — and authenticated for — the incoming payload. More generally, every handler should be audited to guarantee it only mutates records that belong to the repository resolved from `payload.dig('repository', 'full_name')` that was checked in `verify_signature`, mirroring the report's recommendation that authorization scopes not overlap and that the field validated equal the field acted upon.

### Proof of Concept
1. Shipit is configured with two GitHub App installations, `OrgA` and `OrgVictim`, each with its own `webhook_secret` (supported multi-org config, cf. `secrets_double_github_app.yml`).
2. Attacker controls the `OrgA` GitHub App installation (e.g., owns a small repo under OrgA) and thus can compute a valid `X-Hub-Signature` using OrgA's `webhook_secret`.
3. Attacker knows the SHA of a commit belonging to a stack under `OrgVictim` that is pending a required CI check (`ci.require`).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a body containing `"repository": {"owner": {"login": "OrgA"}, ...}` (so `repository_owner` resolves to OrgA for signature verification) but `"sha": "<victim commit sha>"`, `"state": "success"`, `"context": "<required context>"`, signed with OrgA's secret.
5. `WebhooksController#verify_signature` succeeds (OrgA's secret matches OrgA's signature) [2](#0-1) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim's commit (no repository scoping), creating a forged "success" status on it [6](#0-5) .
7. The forged status satisfies `ci.require` for OrgVictim's stack, enabling an unauthorized deploy of that commit.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/models/shipit/commit_checks.rb (L1-2)
```ruby
# frozen_string_literal: true

```

**File:** app/models/shipit/deploy_spec.rb (L1-2)
```ruby
# frozen_string_literal: true

```
