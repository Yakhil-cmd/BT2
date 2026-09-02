### Title
Webhook signature is validated against the organization named in the payload's `repository.owner.login`, but the record actually written is selected by the payload's `repository.full_name` / `sha` — allowing a webhook sender legitimately holding one organization's `webhook_secret` to inject state (e.g. forged commit statuses) into a Stack belonging to a different, unrelated organization tracked by the same Shipit instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* HMAC secret to check against by reading `repository_owner` straight out of the still-unauthenticated request body, then uses that secret to validate the whole raw body. [1](#0-0)  The org name used for secret selection (`repository.owner.login`) and the repository name used afterwards to decide *what gets mutated* (`repository.full_name`, or in the `status` handler, simply a bare commit `sha` with no repository scoping at all) are never cross-checked against each other. [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
Shipit supports hosting multiple GitHub organizations/apps from one instance, each with its own `webhook_secret` in `secrets.github[org]`. [5](#0-4)  On every incoming webhook, the controller:

1. Extracts `repository_owner` from the **unauthenticated** JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). [2](#0-1) 
2. Looks up `Shipit.github(organization: repository_owner)` and verifies the raw body's HMAC against **that organization's** `webhook_secret`. [1](#0-0) 
3. If verification succeeds, it dispatches the entire parsed body to event handlers, none of which re-confirm that the record being modified actually belongs to the organization whose secret was used to authenticate. [6](#0-5) 

The `Handler` base class resolves the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')`. [3](#0-2)  `StatusHandler` goes further and doesn't even use `repository` at all — it matches **any** `Commit` row across the whole database by raw `sha`. [7](#0-6)  Because the value used to choose the verification secret (`repository.owner.login`) and the value(s) used to choose the mutated row (`repository.full_name`, `sha`) live in independent, attacker-controlled JSON fields of the same request body, an entity that legitimately possesses (or configures) the `webhook_secret` for **Org B** can HMAC-sign a payload where `repository.owner.login = "OrgB"` (to pass step 2) while `repository.full_name` (or the bare `sha`) targets a Stack that belongs to **Org A**, a completely unrelated tenant of the shared Shipit instance.

This is exactly the "an organization that authenticated versus the repository that is written" binding called out in scope: the equality `organization_that_signed == organization_owning_the_written_repository` is never enforced; only `organization_that_signed == organization_named_in_body` is checked, and the body is self-authored by the attacker.

### Impact Explanation
Using this gap, a party controlling one org's webhook_secret can:
- Forge a `status` event with `sha` matching any commit on any other tenant's stack and `state: "success"`, silently satisfying `ci.require` checks that gate deploys — a direct path to an **unauthorized deploy** of unreviewed code on someone else's stack, matching the required Critical/High impact category. [4](#0-3) [8](#0-7) 
- Forge `pull_request`/`push` events referencing a foreign `repository.full_name` to archive/unarchive review stacks or trigger `GithubSyncJob` on stacks outside their control. [9](#0-8) 

### Likelihood Explanation
Exploitation requires operating (or having configured/knowing the secret for) one organization already onboarded onto the shared, multi-tenant Shipit deployment — this is the realistic "unprivileged relative to other tenants" attacker the analog rules target (no Shipit session, `ApiClient` token, or GitHub App private key needed; only knowledge of one's own org's webhook secret, which one legitimately possesses as that org's operator). Multi-org configuration is a documented, first-class feature (`lib/shipit.rb#github_app_config`), not an edge case. [10](#0-9) 

### Recommendation
Bind signature verification to the same repository/organization the handler will act on: after verifying the signature, re-derive `repository_owner` from a value tied to the *verified* GitHub App config (e.g., only accept events whose `repository.full_name`'s owner matches the org whose secret validated the signature), or require a single canonical `organization` context per configured webhook_secret and reject payloads whose `repository.owner.login` disagrees with it. Additionally, `StatusHandler` should scope commit lookup by the resolved `Repository`/`Stack` rather than a global `Commit.where(sha:)`.

### Proof of Concept
1. Shipit instance configured with `secrets.github` containing two orgs: `OrgA` (tracks `OrgA/app`, stack S) and `OrgB` (tracks `OrgB/other-repo`), each with distinct `webhook_secret`.
2. Attacker controls/administers `OrgB` and thus knows `OrgB`'s `webhook_secret` (e.g. they set it when installing the Shipit GitHub App for their own org).
3. Attacker crafts a `status` event body:
```json
{
  "sha": "<commit sha of a pending deploy on OrgA's stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgB/other-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgB`'s real `webhook_secret` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner == "OrgB"`, fetches `OrgB`'s app, and the signature checks out — request passes. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` irrespective of `repository`, finds the commit belonging to `OrgA`'s stack, and creates a `success` `Status` for it — satisfying CI requirements and enabling deploy on a stack the attacker never had access to. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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
