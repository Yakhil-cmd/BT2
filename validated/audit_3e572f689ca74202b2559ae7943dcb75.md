### Title
Cross-Repository Commit Status Forgery via Unscoped `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook handler resolves the commit to update purely by `sha`, with no check that the commit belongs to a repository owned by the GitHub organization whose webhook secret authenticated the request. In a multi-organization Shipit deployment, an operator of any one onboarded organization can forge a signed `status` event (using their own organization's `webhook_secret`, which they configured themselves) that fabricates a "success" CI status for a commit belonging to a completely different organization's stack, potentially unblocking an unauthorized deploy there.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to verify a webhook against using an attacker-supplied field of the JSON body itself: [1](#0-0) [2](#0-1) 

This is safe on its own because the org name is inside the signed payload. However, Shipit explicitly supports hosting many GitHub organizations from a single instance, each with its own independent `webhook_secret`: [3](#0-2) [4](#0-3) 

Because each organization's administrator configures (and therefore knows) their own `webhook_secret` value when creating their GitHub App, that administrator can independently sign and POST an arbitrary webhook body directly to `/webhooks` — they do not need GitHub to relay it. The `verify_signature` check only proves the payload was signed by *some* known organization's secret; it never proves the *content* of the payload (e.g. which commit is affected) actually belongs to that organization.

Most event handlers mitigate this by scoping their side effects to a `Stack` resolved from `repository.full_name` in the payload via the shared `Handler#stacks`/`repository_name` helpers: [5](#0-4) 

`StatusHandler`, however, bypasses this scoping entirely and queries `Commit` directly by `sha` across the whole database: [6](#0-5) 

Since `sha` is only indexed together with `stack_id` (not globally unique), and the same commit is legitimately shared by multiple stacks tracking the same repo, `Commit.where(sha: params.sha)` performs a **global lookup with zero organization/repository ownership check**. The write path this triggers is: [7](#0-6) 

which ultimately affects `deployable?`, gating whether a deploy is allowed: [8](#0-7) 

This is precisely the "organization authenticated vs. repository written" trust binding: `verify_signature` proves `organization == OrgA` (the signer), but `StatusHandler#process` writes to `Commit` records without any assertion that `commit.stack.repository.owner == OrgA`.

### Impact Explanation
An operator of any single organization hosted on a shared, multi-tenant Shipit instance can forge a commit status for a `sha` value known to exist in a different organization's tracked repository (commit shas are public information on GitHub), setting `state: "success"` with a `context` matching that stack's required CI check. This can flip `commit.deployable?` to `true` for another organization's stack, which — combined with continuous deployment or a manually-triggered deploy — results in an unauthorized deploy of code the victim organization did not actually validate through CI. This satisfies the High/Critical impact bar of "an unauthorized deploy" via a credential/authorization boundary (organization A's signature) being used to write outside its own authorization scope (organization B's commits).

### Likelihood Explanation
Exploitation requires only knowledge of one organization's own `webhook_secret` (something every onboarded org possesses for itself in a multi-tenant setup) plus the ability to learn a target commit's `sha` and required CI `context` name, both of which are typically discoverable from a public GitHub repository and its `shipit.yml`/CI configuration. No compromise of the victim organization's credentials, GitHub App, or Shipit session is required — only a standing, legitimate (if semi-trusted) relationship with the shared Shipit instance as one tenant among several. This is a plausible insider/multi-tenant-abuse scenario for any Shipit installation using the documented "Using Multiple Github Applications" feature.

### Recommendation
Scope `StatusHandler#process` (and any other handler that mutates state) to the repository/organization whose signature authenticated the request. Concretely, resolve commits only through `stacks` (as `Handler#stacks`/`repository_name` already does for other handlers) rather than an unscoped `Commit.where(sha:)`, and additionally verify that the resolved stack's repository owner matches the organization used in `verify_signature`.

### Proof of Concept
1. Deploy Shipit with the multi-org GitHub App configuration described in `docs/setup.md` (`OrgA` and `OrgB` each with distinct `webhook_secret`s), each with a Shipit stack tracking their own repository.
2. As the administrator of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), craft a JSON body:
```json
{
  "sha": "<sha-of-a-commit-in-OrgB's-tracked-stack>",
  "state": "success",
  "context": "<required-ci-context-for-OrgB-stack>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` succeeds because `repository_owner` resolves to `"OrgA"`, whose secret matches.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit belonging to `OrgB`'s stack, and calls `create_status_from_github!`, recording a fabricated "success" status — with no check that the commit belongs to `OrgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-34)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-230)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

```
