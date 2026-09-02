### Title
Cross-organization/cross-repository commit status forgery via unscoped `StatusHandler` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects a GitHub App/webhook secret to validate an incoming webhook based solely on the attacker-influenced `repository.owner.login` (or `organization.login`) field of the JSON payload, then simply checks the HMAC signature against that org's own secret. Once verification passes, the payload is dispatched to an event handler, but `Shipit::Webhooks::Handlers::StatusHandler` writes a commit status by looking up `Commit.where(sha: params.sha)` **globally**, with no check that the SHA belongs to the repository that authenticated the request. This breaks the equality "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to check the signature against using the repository/organization named in the untrusted JSON payload itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` then HMACs the raw body against that specific organization's own `webhook_secret`: [3](#0-2) 

Once verified, the raw params are dispatched unmodified to whichever handler matches the event type: [4](#0-3) 

The base `Handler` class provides a `repository_name`/`stacks` helper meant to scope processing to the repository named in the payload (correctly used by `PushHandler`): [5](#0-4) [6](#0-5) 

However, `StatusHandler` never uses this scoping. It updates status directly from a global `Commit` lookup keyed only by SHA: [7](#0-6) 

`Shipit` explicitly supports multiple, independently‑configured GitHub App installations (one per organization, each with its own `webhook_secret`), all funneled through the same `/webhooks` endpoint and the same `Commit` table: [8](#0-7) [9](#0-8) 

The equality that is supposed to hold is: `organization whose webhook_secret verified the signature == organization/repository owning the resource being mutated`. `PushHandler` enforces this by re-deriving stacks from `repository.full_name` before acting. `StatusHandler` does not: it trusts `params.sha` in isolation and mutates the `Commit` row for that SHA wherever it happens to exist in the database, regardless of which org's app validated the delivery.

### Impact Explanation
Because git commit SHAs are content-derived and identical across forks/mirrors, an attacker who can trigger a legitimately-signed "status" webhook for **any** repository serviced by **any** configured GitHub App in the Shipit install (e.g., their own organization/fork that has the same GitHub App installed, or any repo where they can post a commit status) can forge a "success" commit status for a SHA that is also tracked as a real commit belonging to an unrelated, sensitive stack in a different organization. Since Shipit gates deploys/merges on required CI statuses (`ci.require` in `shipit.yml`, backed by `Commit`/`Status` records populated by this same webhook path), this allows an unauthorized deploy or merge to proceed by satisfying CI requirements without the actual CI system for the target repository ever running. This matches the "unauthorized deploy" / "cross-repository writes" Critical impact bucket, since the write (a `CommitStatus`) crosses a repository/organization trust boundary that the signature verification was supposed to enforce.

### Likelihood Explanation
Exploitation requires only the ability to have GitHub deliver one legitimately signed "status" webhook event for a repository under any org configured in this Shipit instance (trivial for the attacker's own repo/fork, or any repo they have push/status permissions on within that org) whose commit SHA also exists in the target stack's commit history (trivially true for forks of public repos, which share commit SHAs with upstream, or any case of shared history). No access to `webhook_secret`, `api_clients_secret`, or any Shipit-side credential is required — the attacker only needs to be able to make GitHub emit one real, GitHub-signed status event, which is a normal unprivileged action for a fork/collaborator.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already use `repository_name`/`stacks`) to the repository named in the payload, mirroring `PushHandler`:
```ruby
def process
  Repository.from_github_repo_name(repository_name)
    &.stacks
    &.flat_map(&:commits)
    &.select { |c| c.sha == params.sha }
    &.each { |commit| commit.create_status_from_github!(params) }
end
```
or, more directly, constrain the `Commit.where(sha: params.sha)` lookup with a join/scope on `stack.repository_id == Repository.from_github_repo_name(repository_name)&.id`, rejecting/no-op'ing when the commit's owning repository does not match the repository asserted (and cryptographically bound via signature) in the webhook payload.

### Proof of Concept
1. Configure two GitHub organizations in `secrets.yml` (or use one org and any repo where an attacker has status-write access), e.g. `AttackerOrg` (attacker controls a repo `AttackerOrg/evil`) and `VictimOrg` (owns the tracked stack `VictimOrg/app`).
2. Attacker forks/mirrors a public commit from `VictimOrg/app` into `AttackerOrg/evil` (or otherwise obtains a repo containing the identical commit SHA, e.g. via a fork), so SHA `abc123...` exists in both repos' git history.
3. Attacker (having legitimate write/status permission on `AttackerOrg/evil`) triggers a real GitHub "status" webhook for `AttackerOrg/evil` with `sha=abc123...`, `state=success`, `context=<required-ci-context>`. GitHub signs this payload with `AttackerOrg`'s webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"AttackerOrg"` from the payload, fetches `AttackerOrg`'s `GitHubApp`, and successfully verifies the signature (it is a real, correctly signed GitHub delivery for that org).
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, which matches the `Commit` row belonging to `VictimOrg/app`'s stack (same SHA, different repo), and calls `create_status_from_github!`, marking the victim commit's CI status as `success` for the required context.
6. If `VictimOrg/app`'s `shipit.yml` requires that CI context before deploy, a deploy of that commit can now proceed without the victim's real CI ever running.

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
