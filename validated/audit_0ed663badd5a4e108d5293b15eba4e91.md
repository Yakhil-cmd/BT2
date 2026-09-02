Confirmed: Shipit supports multi-organization GitHub configs, where `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key [1](#0-0) , and `github_organizations` explicitly documents that multiple organizations can be configured simultaneously on one Shipit instance [2](#0-1) .

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` but the affected repository/stack is selected from the unverified `repository.full_name` field, allowing any onboarded organization to forge writes against any other organization's repositories - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate the webhook using an organization identifier taken from the JSON body itself (`repository.owner.login`, falling back to `organization.login`), then validates the *entire* raw request body against that secret [3](#0-2) . Once verification passes, every event handler resolves the actual `Repository`/`Stack` to mutate using a *different* field from the same attacker-controlled body: `payload.dig('repository', 'full_name')` [4](#0-3) . Nothing cross-checks that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` value that was actually used to select the signing secret.

### Finding Description
The binding that should hold is:

`organization whose secret validated the signature == organization owning the repository that gets written to`

Before the fix, this equality is never enforced. `verify_signature` computes `repository_owner` purely from JSON fields, with no relation to which secret is "correct" for the repository named elsewhere in the same payload:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`Shipit.github(organization: repository_owner)` is then used to fetch that organization's `webhook_secret` and validate the HMAC over the raw body [6](#0-5) . Every handler, however, resolves the target repository/stack from an independent field, `repository.full_name`, which the same request body also fully controls:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [7](#0-6) 

Because Shipit explicitly supports hosting multiple GitHub organizations, each with its own `webhook_secret` [1](#0-0) [2](#0-1) , an entity that legitimately possesses one organization's webhook secret (e.g. the admin who configured `secrets.github[:orgA][:webhook_secret]` on their own GitHub organization/App settings) can build an arbitrary JSON body where:
- `repository.owner.login` = `"orgA"` (so the secret lookup and HMAC succeed), and
- `repository.full_name` = `"orgB/victim-repo"` (an unrelated organization's repository that is also connected to the same Shipit instance),

sign the whole body with `orgA`'s secret, and POST it to `/github_webhooks`. `verify_signature` passes because the HMAC is valid for `orgA`, but every downstream handler operates on `orgB/victim-repo`.

Concrete write paths reachable this way:
- `push` → `PushHandler#process` finds `orgB`'s non-archived stacks matching the forged branch and calls `stack.sync_github(expected_head_sha: params.after)` [8](#0-7) .
- `status` → `StatusHandler#process` writes a forged commit status onto any commit in `orgB` matching an attacker-chosen `sha` [9](#0-8) .
- `pull_request` closed/reopened/labeled handlers archive/unarchive `orgB` review stacks based on forged PR state [10](#0-9) [11](#0-10) .

This is structurally the same class of bug as the QV `reviewRecipients` report: a security-relevant decision (which entity is authorized to act) is derived from one part of an attacker-supplied input, while the actual state mutation is keyed off a *different*, uncorrelated part of the same input, letting the acted-upon field diverge from what was actually verified.

### Impact Explanation
This allows cross-repository, cross-organization writes: triggering deploy syncs (`GithubSyncJob`), injecting/overwriting CI statuses on commits, and archiving/unarchiving review stacks belonging to a repository the forging party never authenticated for and does not own. This matches the "Critical - cross-repository writes" impact bucket, since the write is not scoped to the repository the sender's credentials actually correspond to.

### Likelihood Explanation
Requires the attacker to possess a `webhook_secret` for at least one organization already connected to a shared multi-tenant Shipit deployment (i.e., they are a legitimate customer/org-admin for *some* org on the instance, not a fully unauthenticated internet user). Given the rules explicitly list "an organization that authenticated versus the repository that is written" as an in-scope binding to test, and the code confirms the two identifiers are never cross-checked, this is a real, reachable design flaw for any deployment onboarding more than one GitHub organization.

### Recommendation
After signature verification, re-derive the organization/owner from `repository.full_name` (the same field handlers use to select the target) and reject the request (422) unless it matches the organization whose secret validated the signature. Alternatively, verify the signature using the secret resolved from the *target* repository's owner rather than a separately-read `repository.owner.login`/`organization.login` field, so both checks are guaranteed to reference the same owner.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` and `orgB`, each with its own repos and `webhook_secret` (per `github_app_config`) [12](#0-11) .
2. The `orgA` admin, who legitimately knows `orgA`'s webhook secret, crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POSTs to the webhooks endpoint.
4. `verify_signature` resolves `repository_owner == "orgA"`, fetches `orgA`'s secret, and the HMAC matches → request passes [6](#0-5) .
5. `PushHandler` resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")` [4](#0-3)  and calls `stack.sync_github` on `orgB`'s stack, even though the verified identity was `orgA` [8](#0-7) .

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
