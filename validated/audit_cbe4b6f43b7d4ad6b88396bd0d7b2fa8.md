### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the repository acted upon is looked up from the unverified `repository.full_name` field, allowing a holder of one organization's webhook secret to forge events for any other organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). However, every event handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, `MembershipHandler`, etc.) resolves the actual `Repository`/`Stack` to act on from a *different* field in the same payload: `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name`. Because these two fields are independent and both attacker-controlled inside a single JSON body that only needs to satisfy the HMAC of the org picked by `repository.owner.login`, a party holding the webhook secret for organization A can forge a payload whose `repository.full_name` points to a completely different organization B's repository/stack.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
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
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` selects the `GitHubApp` instance (and thus the `webhook_secret`) purely by this `repository_owner` string, one of the top-level keys under `github:` in `secrets.yml` in the multi-org configuration documented in `docs/setup.md`. [2](#0-1) [3](#0-2) 

Every webhook handler, however, resolves the target `Repository`/`Stack` from a *different* key of the same JSON body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)`, `CheckSuiteHandler` schedules check-run refreshes, and `StatusHandler` writes commit statuses - all based on the repository selected by `repository.full_name`, not `repository.owner.login`. [5](#0-4) [6](#0-5) [7](#0-6) 

Because the entire request body is HMAC-signed as a whole (a "checked"/all-or-nothing signature, analogous to the report's "missing unchecked" theme in that the signature check silently protects the wrong sub-field), the signature only proves "this byte-for-byte payload was produced by someone who knows organization A's `webhook_secret`" - it says nothing about which organization's data the payload actually names. `Repository.from_github_repo_name` splits `owner/name` straight out of `repository.full_name` and does `find_by(owner:, name:)` with no additional check that `owner` equals the signing organization (`repository_owner`). [8](#0-7) 

**Attack precondition and equality broken:** the attacker must be a legitimate administrator of at least one GitHub organization/App that Shipit is configured to trust (i.e., they know that org's `webhook_secret`, e.g. because they created/administer the GitHub App for their own org that Shipit's operator installed under a multi-org `secrets.yml`). With that secret they can compute a valid `X-Hub-Signature` for *any* payload body they construct, including one naming `repository.full_name` of a target repository belonging to a different, unrelated organization tracked by the same Shipit instance. This breaks the binding: **organization that authenticated (via `repository_owner` / webhook secret) == repository that is written (via `repository.full_name` in `Repository.from_github_repo_name`)** - which does not hold.

### Impact Explanation
An attacker who controls one trusted-but-unrelated organization's webhook secret can:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha:)` against a victim stack, causing Shipit to sync/re-evaluate deployability status using an attacker-chosen `expected_head_sha` for a repository they do not own.
- Force `StatusHandler` to write fabricated commit statuses on a victim's commits, and `CheckSuiteHandler` to trigger check-run refresh scheduling on victim stacks.
- Potentially interfere with the deploy-readiness gating (commit statuses) of another organization's stacks, which can influence whether "unauthorized" deploys become eligible through continuous delivery, since deploy-readiness in Shipit is largely driven by these very statuses/sync signals.

This is a cross-organization write into stack state that the victim organization never authorized, satisfying the "cross-repository writes" / unauthorized state manipulation bar for this engine's threat model.

### Likelihood Explanation
Requires the attacker to legitimately control the webhook secret of any one organization configured on the same multi-tenant Shipit instance (a realistic scenario for shared/internal Shipit deployments hosting multiple orgs, since webhook secrets are per-organization but the signature-to-repository binding is not enforced). No Shipit session, `ApiClient` token, or GitHub App private key is needed - only knowledge of one org's webhook HMAC secret, which is plausible for any admin of an org already onboarded to the instance.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#repository_name`, enforce that the organization used to select/verify the webhook signature matches the owner of the repository the handler is about to act on - e.g., reject the event if `payload.dig('repository','owner','login')` differs from the owner portion of `payload.dig('repository','full_name')`, or better, have handlers resolve the repository strictly from the already-verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `org-attacker` (attacker is admin, knows `webhook_secret_A`) and `org-victim` (has a stack tracked by Shipit).
2. Attacker crafts JSON body:
```json
{
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, body)>` using the known secret for `org-attacker`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "org-attacker")` and validates successfully against the attacker's own secret.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("org-victim/victim-repo")` and calls `sync_github(expected_head_sha: <attacker sha>)` on the victim's stack - an action the victim organization never authorized nor signed for.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
