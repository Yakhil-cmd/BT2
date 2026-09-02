### Title
Webhook signature verified against `repository.owner.login`'s GitHub App while all downstream handlers act on the unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check the request signature against based on `repository_owner`, i.e. `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . But every webhook handler that actually mutates state (`PushHandler`, the `pull_request` handlers, etc.) resolves the target `Repository`/`Stack` from a completely different, unverified field: `payload.dig('repository', 'full_name')` [3](#0-2) . In a Shipit installation configured with multiple GitHub Apps/organizations (`config/secrets.yml` keyed by org, as documented) [4](#0-3) [5](#0-4) , the field used to pick the verifying secret (`repository.owner.login`) and the field used to identify which repository/stack is written to (`repository.full_name`) are never checked for consistency.

### Finding Description
The binding that should hold is: `organization whose webhook secret validated the request == organization that owns the repository being mutated`. Before the attacker's forged request, this equality holds implicitly because a real GitHub webhook always carries a consistent `repository.owner.login`/`repository.full_name` pair. After a forged request, an attacker who knows (or controls) the webhook secret for **any one** configured organization (Org A, e.g. because they are a legitimate contributor/webhook admin of Org A, or Org A has `webhook_secret` unset — `return true unless webhook_secret` bypasses HMAC entirely [6](#0-5) ) can craft a JSON body where:
- `repository.owner.login = "OrgA"` (used only for signature verification / secret selection)
- `repository.full_name = "OrgB/some-other-repo"` (used by every handler to find the actual `Repository`/`Stack`)

`Shipit.github(organization: repository_owner)` looks up Org A's `GitHubApp` and verifies the signature purely against Org A's secret [7](#0-6) ; it never cross-checks that `full_name` actually belongs to Org A. Once verification passes, `WebhooksController#create` dispatches the raw, unverified `params` to `Shipit::Webhooks.for_event(event)` handlers [8](#0-7) , and each handler independently re-derives the target repository from `full_name` via `Repository.from_github_repo_name` [3](#0-2) , e.g. `PushHandler#process` triggers `stack.sync_github` for whatever stacks match that repo [9](#0-8) , and pull-request handlers archive/unarchive review stacks or mutate `PullRequest` records for that repo [10](#0-9) .

This is structurally the same class of bug as the referenced report: a value used for authorization/verification (`updateActionTimestampByCreditor`'s creditor check / here, the signing organization) is not the same value that the privileged action is actually performed against (`flashActionByCreditor`'s target account / here, `repository.full_name`).

### Impact Explanation
An attacker who legitimately controls (or has compromised) the webhook secret of **any** organization configured in a multi-org Shipit deployment can forge push/status/check_suite/pull_request/membership events that get accepted as authentic for **any other configured organization's repositories**. This can:
- Trigger unauthorized `GithubSyncJob`/`sync_github` calls, forged commit `status` records, or forged `check_suite` results that influence CI-gated deploy decisions on stacks belonging to a different organization [9](#0-8) .
- Archive/unarchive review stacks or manipulate pull-request state belonging to a different organization's repository [11](#0-10) .
- Combined with continuous deployment (`continuous_deployment: true`), forged `status`/`check_suite` events can influence whether an unauthorized deploy is triggered — meeting the "unauthorized deploy" bar for Critical impact, though the direct write here is cross-repository/cross-organization state manipulation, matching the High-severity "cross-repository writes" / "unauthenticated read/write of stack state" criteria.

### Likelihood Explanation
Requires the multi-org GitHub App configuration schema (`config/secrets.yml` with organization-keyed `github:` sections) to be in use, and requires the attacker to possess a valid webhook secret for at least one configured organization (or for one org to have no `webhook_secret` set, which `docs/setup.md` explicitly marks optional) [12](#0-11) . This is plausible for organizations that self-manage their own GitHub App webhook secret but are onboarded into a shared Shipit instance serving multiple orgs — a documented, supported configuration [5](#0-4) .

### Recommendation
After signature verification succeeds, cross-check that `repository_owner` (the organization whose secret validated the signature) matches the owner segment of `repository.full_name` before dispatching to handlers, e.g. reject the request if `payload.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)` is false. Alternatively, derive `repository_owner` strictly from `full_name` so the same value is used for both secret selection and repository resolution.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled webhook secret) and `OrgB` (victim, has a stack with `continuous_deployment: true`), per the documented multi-org schema [5](#0-4) .
2. Attacker sends `POST /webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with `OrgA`'s `webhook_secret`, and a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret [1](#0-0) .
4. `PushHandler#process` resolves `stacks` from `repository.full_name = "OrgB/victim-repo"` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` [9](#0-8)  on `OrgB`'s stack, despite the request never being signed by `OrgB`.

**Caveat/uncertainty:** This analysis is based on statically reading the controller and handler code; I could not execute the test suite in this ask-only environment to empirically confirm the forged request is accepted end-to-end (e.g. interactions with `GithubSyncJob`'s later GitHub API calls, or any additional org-scoping I may have missed in `Repository.from_github_repo_name`). I recommend a Devin session to write and run an integration test reproducing this cross-organization forgery to confirm exploitability before treating this as fully verified.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
