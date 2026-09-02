## Title
Cross-organization webhook confusion: signature is verified against `repository.owner.login`, but the target repository/stack is resolved from the independently-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController` selects which GitHub App/organization webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) in the incoming payload, but the individual event handlers resolve the target `Stack`/`Repository` using a *different* field of the same payload: `repository.full_name`. Because Shipit is multi-tenant (one Shipit instance can track repositories across many GitHub organizations, each with its own webhook secret), an actor who legitimately knows the webhook secret for **one** tracked organization can forge a signed request whose `repository.full_name` points at a stack belonging to a **different** organization, causing Shipit to act on that unrelated stack.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret used to verify `X-Hub-Signature` purely from `repository_owner`: [1](#0-0) [2](#0-1) 

The HMAC only proves that *whoever set up the webhook secret for the organization named in `repository.owner.login`* produced the request; it does not constrain any other field inside the same JSON body other than the fact that the whole raw body was signed with that particular secret. Since a Shipit deployment tracks many organizations, each with its own independently configured webhook secret (`Shipit.github(organization:)` / `github_app_config`): [3](#0-2) 

an admin who owns the webhook secret for organization A can compute a valid HMAC over *any* payload body they construct, including one where `repository.owner.login` is set to `"orgA"` (to pass `verify_signature`) while `repository.full_name` is set to `"orgB/some-repo"`.

The generic handler base class then looks up the target stack purely from `repository.full_name`, with no cross-check against the organization that authenticated the request: [4](#0-3) [5](#0-4) 

For example, `PushHandler` will run `stack.sync_github(expected_head_sha:)` against whatever stack matches `repository.full_name`, without any relationship to the org that signed the request: [6](#0-5) 

This is directly analogous to the `Perpetual.liquidateFrom` issue: there, the function trusted a caller-supplied `from` address without validating that it matched the party actually authorized to act; here, the controller trusts a caller-supplied `repository.full_name` to select the object being written to, while only validating a *different* field (`repository.owner.login`) against the signature. The binding that should hold is:

`organization whose secret authenticated the HMAC == organization owning the repository/stack actually acted upon`

but the code never enforces `repository.full_name.split('/').first == repository_owner`.

### Impact Explanation
An attacker who legitimately controls the webhook secret for any one organization tracked by a shared/multi-tenant Shipit instance (e.g., an org admin who configured the GitHub App/webhook integration for their own org) can forge signed webhook deliveries that are attributed to, and act on, a completely different organization's stacks. Depending on which event handler fires, this can:
- Trigger `GithubSyncJob`/`stack.sync_github` for another org's stack, injecting synthetic commit history via `Repository#from_github_repo_name` lookup.
- Create/modify `Status`/`CheckSuite` state on another org's commits, which feeds into `Commit#deployable?` checks gating continuous deployment - potentially enabling an **unauthorized deploy** to proceed on a stack the attacker has no legitimate access to.
- Provision/archive `ReviewStack`s belonging to a different organization via `pull_request` handlers, since those also key off `repository.full_name`.

This crosses a repository/organization trust boundary that the signature check is nominally supposed to enforce, matching the "cross-repository writes / unauthorized deploy" impact class.

### Likelihood Explanation
Exploitability requires the attacker to know a valid webhook secret for at least one organization tracked by the Shipit instance — a realistic scenario for any multi-tenant deployment where multiple, mutually-distrusting GitHub organizations/teams are onboarded onto a shared Shipit instance and each organization's admin independently manages their own webhook secret. No GitHub App private key, `api_clients_secret`, or Shipit session is required — only knowledge of one org's webhook secret, which is inherently distributed to org-level, not app-level, administrators.

### Recommendation
After verifying the signature, cross-check that the organization used to select the webhook secret (`repository_owner`, from `repository.owner.login`/`organization.login`) matches the owner segment of `repository.full_name` (and any other identifying fields the handler will act on) before dispatching to handlers. Reject the request (422) on mismatch.

### Proof of Concept
1. Shipit tracks `orgA/repo1` (webhook secret `S_A`) and `orgB/repo2` (webhook secret `S_B`), unrelated organizations.
2. Attacker, who legitimately administers `orgA`'s GitHub webhook config and thus knows `S_A`, crafts a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/repo2"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` and POSTs directly to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner == "orgA"`, fetches `Shipit.github(organization: "orgA")`, verifies HMAC successfully with `S_A`.
5. `PushHandler#process` (via `Handler#stacks` / `Repository.from_github_repo_name("orgB/repo2")`) resolves and acts on `orgB`'s stack, even though the signature was never computed with `orgB`'s secret and the attacker has no relationship to `orgB`.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
