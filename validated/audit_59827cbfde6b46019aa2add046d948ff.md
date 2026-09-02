### Title
Webhook signature is verified against the organization asserted in the untrusted payload, allowing a Shipit tenant with only their own org's `webhook_secret` to forge events (including arbitrary commit statuses) attributed to a different organization/repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against based on a field taken from the *same, unauthenticated* request body it is trying to validate. In a multi-organization Shipit deployment (a documented, supported configuration), any organization whose GitHub App is registered with Shipit can forge webhook payloads that claim to originate from, or write to, a completely different organization/repository/stack, because nothing binds the org whose secret produced the signature to the org/repo the payload content is actually applied to.

### Finding Description
`verify_signature` derives the signing organization purely from request JSON: [1](#0-0) 

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

`repository_owner` is read straight from the attacker-supplied JSON body, before any signature has been proven valid. Shipit explicitly supports multiple, independently-configured GitHub Apps/organizations, each with its own `webhook_secret`, as documented and tested: [3](#0-2) [4](#0-3) 

Because the secret used for HMAC verification is chosen from the very payload being verified, an attacker who legitimately controls one onboarded organization ("OrgOne", with its own real `webhook_secret`) can:
1. Build a JSON body whose `repository.owner.login` = `"OrgOne"` (so `Shipit.github(organization: "OrgOne")`'s real secret is selected and the HMAC will validate), but whose `repository.full_name` = `"OrgTwo/some-repo"` (a repository belonging to a different tenant org tracked by the same Shipit instance).
2. Sign the raw body with OrgOne's own genuine `webhook_secret` and send it to the shared `/webhooks` endpoint.
3. `verify_signature` succeeds because OrgOne's secret does match OrgOne-labelled owner field, satisfying `verify_webhook_signature`: [5](#0-4) 

Once verified, the shared `create` action dispatches to handlers keyed entirely off the (unbound) `repository.full_name`/`sha` fields: [6](#0-5) 

The most severe instance is `StatusHandler`, which doesn't even use the repository at all — it matches purely by commit `sha` across the *entire* Shipit database: [7](#0-6) 
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This lets a request "authenticated" as OrgOne write a fabricated `state: "success"` status for any commit SHA tracked by Shipit, regardless of which organization/repository actually owns that commit. `PushHandler` and `CheckSuiteHandler` are similarly bound only by `repository.full_name` from the body, letting OrgOne trigger `sync_github`/check-run refresh for OrgTwo's stacks: [8](#0-7) [9](#0-8) 

Downstream, a forged successful commit status feeds directly into deploy gating logic: [10](#0-9) 
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
```
and into merge-queue scheduling via `add_status`: [11](#0-10) 

The binding that should hold is: `organization whose secret authenticated the request == organization/repository the payload's content is applied to`. Before the attacker's forged request, this equality holds trivially (Shipit only ever receives genuine GitHub webhooks, where GitHub itself guarantees `repository.owner.login` matches the repo being described). After the forged request, the equality is broken: the authenticating organization (OrgOne) differs from the written-to repository/commit (belonging to OrgTwo or any other tenant), yet the controller never re-checks this.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. Concretely, a tenant organization admin (who only possesses their own org's `webhook_secret`, not any elevated Shipit credential) can:
- Mark arbitrary commits belonging to other tenants' repositories as `success`, unblocking their `deployable?` check and merge-queue scheduling — leading to an **unauthorized deploy or merge** for a repository/organization the attacker has no legitimate access to.
- Force `GithubSyncJob`/`sync_github` and check-run refresh cross-tenant, causing Shipit to write commit/task state for another organization's stack.

This satisfies the Critical criterion "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Requires only that the Shipit instance is configured with more than one GitHub organization (a documented, supported feature — `docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), and that the attacker controls (as a normal, unprivileged user of that one organization's own GitHub App / repo) that organization's `webhook_secret`, which they legitimately need to configure the webhook on GitHub's side. No Shipit session, `ApiClient` token, or privileged account is needed — only the ability to craft an HTTP POST with a correctly computed HMAC using a secret the attacker is expected to hold for their own tenant.

### Recommendation
After verifying the HMAC, cross-check that the organization whose secret validated the signature actually matches the organization portion of `repository.full_name` (and any other repository identifiers used by handlers) before dispatching to handlers. Additionally, `StatusHandler` should scope its `Commit.where(sha:)` lookup to commits belonging to the repository named in the verified payload, not to the entire `Commit` table.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`, "Using Multiple GitHub Applications") with two organizations, `OrgOne` and `OrgTwo`, each with a distinct `webhook_secret`, both tracking a repository/stack in Shipit.
2. As the (unprivileged relative to OrgTwo) administrator of `OrgOne`, who legitimately knows only `OrgOne`'s `webhook_secret`, craft a `status` webhook JSON body:
```json
{
  "sha": "<sha of a commit belonging to OrgTwo/some-repo tracked by Shipit>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgOne/irrelevant-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgOne_webhook_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` and validates successfully (own secret matches own body).
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — independent of the `OrgOne` binding — and creates a fabricated `success` status on the OrgTwo commit, potentially unblocking its `deployable?` check and merge-queue scheduling (`Commit#add_status`/`schedule_merges`) for a repository the attacker does not control.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
