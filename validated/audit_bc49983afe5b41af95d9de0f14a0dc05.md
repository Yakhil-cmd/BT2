This confirms the vulnerability. In a "multiple GitHub Applications" deployment (documented feature, `docs/setup.md:182-209`), each organization has its own `webhook_secret`. The `WebhooksController#verify_signature` looks up which secret to check against using `repository_owner`, which is `params.dig('repository', 'owner', 'login')` — a value taken directly from the attacker-controlled JSON body [1](#0-0) . The organization named there is only used to *pick the HMAC key*; it is never cross-checked against the `repository.full_name` field that the event handlers actually use to locate and mutate records [2](#0-1) .

Because a webhook installed on `OrgOne` only proves knowledge of `OrgOne`'s `webhook_secret`, and `Shipit.github(organization:)` resolves that secret straight from `github_app_config(organization)` keyed by the attacker-supplied `repository.owner.login` [3](#0-2) , an attacker who legitimately controls `OrgOne`'s GitHub App/webhook secret can build a raw JSON body whose `repository.owner.login` is `"OrgOne"` (so the signature validates) but whose `repository.full_name` is `"OrgTwo/victim-repo"` (a completely unrelated, unaffiliated organization/repo tracked by the same Shipit instance). Handlers such as `PushHandler`, `StatusHandler`, and the pull-request handlers resolve the target purely via `Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) [5](#0-4) , with no verification that `full_name`'s owner matches the org whose secret produced the signature.

This is exactly analogous to the Mango bug: the check binds trust to one field (`repository_owner`/HMAC key selection) while the code acts on a different, unchecked field (`repository.full_name`) from the same untrusted payload — an "organization that authenticated" vs. "repository that is written" mismatch.

### Title
Webhook signature verification binds trust to the payload's `repository.owner.login` but handlers act on the unchecked `repository.full_name`, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `repository_owner`, a value read straight out of the untrusted JSON payload (`params.dig('repository', 'owner', 'login')`). In multi-organization deployments (a documented, supported configuration where each GitHub organization has its own `webhook_secret`), this lets an attacker who controls one organization's legitimate webhook secret sign an arbitrary payload as that organization while setting `repository.full_name` to reference a repository belonging to any *other* configured organization on the same Shipit instance.

### Finding Description
`verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and then verifies `X-Hub-Signature` against that organization's `webhook_secret` [6](#0-5) . `repository_owner` is derived entirely from attacker-controlled JSON:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [7](#0-6) 

Once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches the same raw payload to handlers [8](#0-7) . Every handler resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` [2](#0-1) , and `Repository.from_github_repo_name` does a bare `owner/name` DB lookup with no relation back to the signing organization [5](#0-4) .

`Shipit.github(organization:)` resolves per-organization app configs (including `webhook_secret`) keyed by that same attacker-influenced string, confirming the secret selection is fully payload-driven [3](#0-2) . Multi-organization configuration with independent `webhook_secret`s per org is an explicitly documented and supported setup [9](#0-8) .

Because the signature only proves "the sender knows OrgA's secret," but never proves "the payload's `repository.full_name` actually belongs to OrgA," a party with legitimate webhook access to OrgA can forge events (pushes, commit statuses, check suites, pull-request open/close/label changes) against any repository/stack belonging to OrgB, OrgC, etc., configured on the same Shipit instance.

### Impact Explanation
This breaks the equality "organization that authenticated == repository that is written." Concretely:
- `PushHandler` can trigger `stack.sync_github(expected_head_sha:)` for a victim org's stack [10](#0-9) , forcing spurious GitHub syncs / potentially manipulating perceived deploy state.
- `StatusHandler`/check-run flows feed into `MergeRequest#reject_unless_mergeable!` and `all_status_checks_passed?`, which gate the merge queue's `merge!` call that actually merges pull requests and pushes to GitHub via the victim organization's own `stack.github_api` [11](#0-10) . Forged/falsified commit-status webhooks can push a merge request past status gating checks it would not otherwise satisfy, resulting in an unauthorized merge into a repository the attacker's organization has no authorization over.
- Pull-request `labeled`/`unlabeled`/`closed`/`reopened` handlers can archive/unarchive/provision review stacks belonging to a victim org's repository.

This qualifies as a High-severity issue per the rules ("escalation into `Shipit.github_teams` authorization" / cross-organization state manipulation) and can escalate to an effectively unauthorized merge/deploy action on a repository the attacker's organization does not own, crossing the explicit trust boundary between organizations hosted on the same Shipit instance.

### Likelihood Explanation
Requires only that: (1) the Shipit instance is configured with multiple GitHub organizations (a documented supported configuration, `docs/setup.md`), and (2) the attacker has legitimate write access to one of those organizations' webhook configuration (i.e., is an admin of one tenant org, not a privileged Shipit user or GitHub org admin of the victim). This is a realistic multi-tenant configuration and the exploit requires only crafting an HTTP POST with a mismatched `repository.owner.login` / `repository.full_name` pair, no additional access.

### Recommendation
After computing `github_app` from `repository_owner`, additionally verify that `repository_owner` matches the owner encoded in `repository.full_name` (and, for events without a `repository` key, the `organization.login`) before dispatching to handlers — i.e., add an explicit equality check binding the signing organization to the repository the payload claims to modify, analogous to the recommended `check!(utp_config.address.eq(mango_account_ai.key), ...)` fix in the Mango report.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. As an administrator of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret` (this is a normal capability of an org's own App admin, not privileged Shipit/GitHub access to `OrgB`).
3. Craft a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist in OrgB/victim-repo>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
4. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, payload)` and POST it to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully because it was computed with `OrgA`'s real secret.
6. `PushHandler#process` then looks up stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on a stack the attacker (as `OrgA` admin) has no legitimate authority over — demonstrating a cross-organization webhook forgery that can be extended to status/check-run/PR-label events with higher-impact consequences (merge-queue manipulation).

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```
