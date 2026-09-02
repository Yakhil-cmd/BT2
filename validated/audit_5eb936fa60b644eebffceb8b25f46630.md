This confirms the vulnerability. The `StatusHandler` at [1](#0-0)  looks up commits by SHA alone (`Commit.where(sha: params.sha)`), with no cross-check against the organization used to select the verification secret. Combined with `PushHandler` and other handlers using `payload.dig('repository', 'full_name')` for repository lookup, this confirms the binding break.

### Title
Webhook signature verification keys off `repository.owner.login` while all event handlers act on `repository.full_name`, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` is used to validate the HMAC signature based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), but every event handler (`Handler#repository_name`, used by `PushHandler`, `StatusHandler` via `Commit.where(sha:)`, `PullRequest::*Handler`) resolves the target repository/stack from the independent `repository.full_name` field of the same JSON body. Because the HMAC covers the raw POST body as a whole but nothing ties `repository.owner.login` to `repository.full_name`, an attacker who legitimately controls a GitHub App installation for their own organization (and therefore genuinely knows that org's `webhook_secret`) can forge a payload where `repository.owner.login` names their own org (to pass signature verification) while `repository.full_name` names a completely different, victim organization/repo configured in the same multi-tenant Shipit instance.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` extracts the "authenticating organization" strictly from `repository.owner.login`/`organization.login`: [2](#0-1) [3](#0-2) 

This organization is used only to pick `Shipit.github(organization: ...)`'s `webhook_secret` for the HMAC check in `GitHubApp#verify_webhook_signature`: [4](#0-3) 

Shipit explicitly supports hosting multiple, mutually untrusted GitHub organizations/App installations in one instance (`docs/setup.md`'s "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`). Each org has its own distinct `webhook_secret`, and `Shipit.github(organization:)` looks up the correct app config by that key: [5](#0-4) 

However, once signature verification passes, `WebhooksController#create` dispatches the *entire attacker-controlled JSON body* to handlers without re-deriving or re-checking the organization used for verification: [6](#0-5) 

All handlers resolve the target repository purely from `repository.full_name`, e.g. the base `Handler`: [7](#0-6) 

and `Repository.from_github_repo_name` simply splits `owner/name` from that string with no relation back to the verified organization: [8](#0-7) 

`PushHandler` uses `stacks` (derived from `full_name`) to trigger `sync_github`: [9](#0-8) , and `StatusHandler` updates commit statuses purely by matching `sha` globally across the whole database, with zero repository/organization scoping at all: [1](#0-0) .

This breaks the binding: `organization authenticated by verify_signature` ≠ `repository/stack actually written by the handler`. GitHub itself would never produce a payload where `repository.owner.login` and `repository.full_name`'s owner segment diverge, but Shipit never enforces that invariant on the payloads it accepts, since it only checks the signature against whatever organization the attacker names in `repository.owner.login`.

### Impact Explanation
An attacker who operates a legitimate GitHub App installation for Organization B (and thus genuinely possesses OrgB's `webhook_secret`, requiring no compromise of Shipit or GitHub) can POST directly to `/webhooks` a forged, self-signed payload where:
- `repository.owner.login` = `"OrgB"` (selects OrgB's real secret for `verify_webhook_signature`, which passes since attacker computes the correct HMAC)
- `repository.full_name` = `"OrgA/victim-repo"` (a completely unrelated organization/repo hosted on the same Shipit instance, per the documented multi-org configuration)

This lets the attacker forge, for example:
- `status` events, setting arbitrary CI status (`state: success`) on any commit SHA anywhere in the database (`StatusHandler` has no repository scoping at all), which can satisfy `ci.require`/blocking-status checks and enable an unauthorized deploy or merge-queue merge of a commit that never actually passed CI on OrgA's repo.
- `push` events, triggering `GithubSyncJob`/`stack.sync_github` for OrgA's stacks.
- `pull_request` events, provisioning/archiving OrgA review stacks or manipulating merge requests.

This is a cross-organization/cross-repository forgery that results in an unauthorized deploy/merge action being taken on a repository the attacker has no legitimate access to, crossing the "authenticated organization vs. repository being written" trust boundary described in scope.

### Likelihood Explanation
Requires only that the Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration) and that the attacker controls one of those orgs' GitHub App installations (i.e., is a legitimate but low-privilege tenant of the same Shipit instance). No access to any other org's secrets, no compromise of GITHUB_TOKEN, no `ApiClient` token, and no Shipit session is required — only the ability to send an HTTP POST with a correctly computed HMAC using a secret the attacker legitimately owns.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after establishing the authenticated organization, re-validate that `repository.full_name`'s owner segment (and/or `organization.login`) matches the organization whose secret validated the signature before dispatching to handlers, and reject the request otherwise. Additionally, `StatusHandler` should scope commit lookups by the verified repository, not by a global SHA match.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org setup), with `OrgA/app` deployed as a stack.
2. As the attacker, who legitimately runs the `OrgB` GitHub App and knows `OrgB`'s `webhook_secret`, craft a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha on OrgA/app>",
  "state": "success",
  "context": "ci/required",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/app" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgB_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgB")` from `repository.owner.login`, verifies successfully using the attacker's own secret.
5. `StatusHandler#process` matches `Commit.where(sha: params.sha)` on OrgA's actual commit and records a forged "success" status, satisfying deploy/merge CI requirements for OrgA without ever going through GitHub or OrgA's real webhook secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

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
