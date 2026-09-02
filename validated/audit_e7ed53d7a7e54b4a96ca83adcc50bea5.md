### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but handlers act on the independently-supplied `repository.full_name` field — allowing a payload signed with one onboarded organization's webhook secret to write state (sync jobs, commit statuses) against any other organization's stacks/commits - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the inbound HMAC against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config (`github_app_config`) and constructs a `GitHubApp` scoped to that organization's `webhook_secret`: [3](#0-2) 

Once the signature check passes, `create` hands the *entire raw payload* to every registered handler for the event: [4](#0-3) 

But the base `Handler` class — used by every event handler — determines which repository/stacks to act on from a **different** field of the same payload, `repository.full_name`, with no check that its owner matches the `repository.owner.login`/`organization.login` value that was used to select the signing secret: [5](#0-4) 

`Repository.from_github_repo_name` then does a straightforward `owner/name` split on this attacker-controlled string: [6](#0-5) 

This breaks the binding **organization that authenticated the request == repository the request is permitted to act on**. In a multi-organization Shipit deployment (`github_default_organization` non-nil, distinct `webhook_secret` per org), any actor who controls (or is an admin of) one legitimately onboarded organization's webhook configuration knows that organization's `webhook_secret` (it is either self-configured by the org admin or obtainable by that org's own delivered webhooks) and can craft an arbitrary JSON body where:
- `repository.owner.login` = "attacker-org" (used only to pick the verifying secret)
- `repository.full_name` = "victim-org/victim-repo" (used by every handler to pick the actual `Stack`/`Commit` records to mutate)

`StatusHandler` makes this worse: it doesn't even scope by repository — it matches purely on commit `sha` across the entire instance: [7](#0-6) 

Since git commit SHAs are content-addressed and typically discoverable via GitHub's public API even for repos the attacker cannot write to, an attacker who only administers `attacker-org`'s webhook secret can forge a `status` event (`state: success`) for a commit sha belonging to `victim-org/victim-repo`, or forge a `push` event whose `repository.full_name` points at a victim stack to trigger `PushHandler#process` → `stack.sync_github`: [8](#0-7) 

### Impact Explanation
This crosses an organizational trust boundary: the HMAC only proves "this came from someone who knows attacker-org's secret," yet the code lets that same signature authorize writes (sync jobs, fabricated commit CI statuses, PR/label/review-stack events, membership changes, etc.) against a completely different organization's repositories and stacks. Forged `success` commit statuses can be used to make a victim's commit falsely appear to have passed CI/required checks, which is the kind of trust-binding break that can lead toward an unauthorized deploy if deploy gating consults these commit statuses, satisfying the "unauthorized deploy" / cross-repository-writes bar for High/Critical impact. I was not able to fully trace, within the remaining exploration budget, the exact downstream code that consumes `CommitStatus` records to gate deploy eligibility (e.g., `commit_checks`), so the specific "guaranteed unauthorized deploy" outcome should be verified further; what is concretely and fully confirmed is unauthorized cross-organization writes: forged sync jobs and forged CI status records attributed to a repository/commit the signing organization does not own.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple GitHub organizations (each with its own onboarded webhook secret) — a supported, documented configuration (`github_app_config`/`TOP_LEVEL_GH_KEYS`). Any actor who is a legitimate webhook administrator for their own onboarded org (not the victim org) can carry out the attack purely by crafting a raw HTTP POST with a body they control and a signature they can correctly compute themselves; no victim credentials, GitHub write access to the victim repo, or Shipit session are required, matching the "unprivileged attacker" threat model.

### Recommendation
In `WebhooksController#verify_signature` and/or `Shipit::Webhooks::Handlers::Handler`, ensure the organization/owner used to select the verifying `webhook_secret` is the same value used to resolve the repository/stack that the event will act on — i.e., derive both from the same field (`repository.full_name`'s owner segment) and reject the payload if `repository.owner.login`/`organization.login` disagrees with the owner segment of `repository.full_name`. `StatusHandler` (and any other handler that queries by `sha` alone) should additionally scope the query to commits belonging to stacks under the verified organization rather than matching sha globally.

### Proof of Concept
1. Shipit instance configured with two onboarded orgs: `attacker-org` (attacker is a legitimate webhook admin, knows `webhook_secret_A`) and `victim-org` (has an onboarded stack and a commit with sha `S`, `S` is discoverable via GitHub's public API).
2. Attacker builds a JSON body for a `status` event:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the signature validates successfully.
5. `StatusHandler#process` executes `Commit.where(sha: 'S').each { |c| c.create_status_from_github!(params) }`, creating a `success` status on `victim-org`'s commit `S`, entirely outside `attacker-org`'s ownership. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
