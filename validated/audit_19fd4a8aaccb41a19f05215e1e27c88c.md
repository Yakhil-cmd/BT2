This confirms the vulnerability. The finding is valid.

### Title
Cross-org webhook confusion allows attacker-authenticated `pull_request:assigned` payload to overwrite a victim repository's PullRequest assignee metadata - ([File: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to verify a webhook against using `repository.owner.login`, while `PullRequestAssignedHandler#process` resolves the target repository/PullRequest to mutate using the independent `repository.full_name` field from the same JSON body. Because these two payload fields are never cross-checked, an attacker who controls (or whose org lacks a configured `webhook_secret` for) one tenant org in a multi-org Shipit deployment can forge a `pull_request` `assigned` webhook that authenticates as their own org but names a victim org/repo's PR, causing `Shipit::PullRequest#update(github_pull_request: ...)` to be called on the victim's record with attacker-supplied data.

### Finding Description
The broken binding is: `org used to select the webhook signature secret` (`WebhooksController#repository_owner`, computed as `params.dig('repository', 'owner', 'login')`, feeding `Shipit.github(organization: repository_owner)` in `verify_signature`) MUST equal `org owning the Repository/Stack/PullRequest actually mutated` (derived from `params.repository.full_name` inside `AssignedHandler#repository` / `AssignedHandler#pull_request`). [1](#0-0) [2](#0-1) 

`repository_owner` and `repository.full_name` are two independently attacker-controlled fields of the same raw JSON POST body; nothing enforces they refer to the same GitHub organization.

In `PullRequestAssignedHandler`, the handler looks up the target repository purely from `params.repository.full_name` and finds the matching `PullRequest` scoped only by that repository's stacks, then writes the whole attacker-controlled `pull_request` sub-object onto it: [3](#0-2) 

Signature verification is per-organization and, critically, is a no-op when that organization has no configured `webhook_secret`: [4](#0-3) 

`Shipit.github(organization:)` looks up the app config keyed by that organization name in the multi-org schema (documented and supported): [5](#0-4) [6](#0-5) 

**Attack flow (multi-org deployment, e.g. `config/secrets.yml` with `github: { attacker-org: {...}, victim-org: {...} }`):**
1. Attacker sends `POST /webhooks` directly (they can send arbitrary HTTP requests to the host per the threat model) with header `X-Github-Event: pull_request` and body: `action: "assigned"`, `number: <victim PR number>`, `pull_request: { assignees: [{login: "attacker"}], ... }`, `repository: { full_name: "victim-org/victim-repo", owner: { login: "attacker-org" } }`, `sender: { login: "attacker" }`.
2. Attacker computes/knows the signature for `attacker-org` — either because they legitimately control that org's own webhook secret, or (even without any secret knowledge) because `attacker-org`'s `webhook_secret` is unset/`nil` in the Shipit config (the shipped example configs literally default it to blank: `webhook_secret: # nil`), in which case `verify_webhook_signature` returns `true` unconditionally regardless of the signature header supplied.
3. `verify_signature` resolves `repository_owner = "attacker-org"`, verifies successfully (attacker's own secret, or no secret at all), and the request proceeds.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `AssignedHandler`, which resolves `repository` from `params.repository.full_name = "victim-org/victim-repo"` — a real victim-owned `Shipit::Repository` row — and finds the real victim `PullRequest` by `number` scoped to that repository's stacks.
5. `pull_request.update(github_pull_request: params.pull_request)` persists attacker-controlled `assignees`/`labels`/`title`/etc. onto the victim's PR record.

Existing guards do not stop this: `verify_signature` only checks that *some* org's secret matches — it never confirms that org equals the org owning the repository named in `repository.full_name`; `ExplicitParameters` only validates JSON shape/types, not cross-field consistency; `drop_unhandled_event` and `check_if_ping` are irrelevant; there is no model-level validation tying `repository.owner.login` to `repository.full_name`.

### Impact Explanation
An attacker-authenticated request (verified only against their own, or an unset, webhook secret) causes a write to another tenant's `Shipit::PullRequest` record (assignees, labels-adjacent metadata via `github_pull_request`), which is a cross-tenant data-integrity break: "a payload for one repository mutating another's ... stack/commit/task" analog for PR records. This is repeatable per victim PR number and per known victim `repository.full_name`, requiring no per-request secret if the attacker's own org (or any org in the shared config) has a blank `webhook_secret`. Blast radius spans all repositories/orgs hosted on the same multi-tenant Shipit instance. This PR-assignee metadata is display data; if any downstream merge-authorization/display logic trusts `PullRequest#assignees` written this way, it inherits the corruption, but the direct, demonstrable impact here is unauthorized cross-tenant record mutation.

### Likelihood Explanation
Requires: (a) the Shipit instance uses the multi-org GitHub App config schema (documented, supported feature for multi-tenant setups), (b) the attacker controls, or can name, at least one org configured in that schema whose `webhook_secret` is blank (the default/placeholder value in every shipped example config) — or otherwise possesses a valid secret for their own org, and (c) the attacker knows/guesses a victim `full_name` and PR `number` (both are public GitHub information). No Shipit session, API token, or victim secret is needed. This is a low-cost, repeatable attack purely through crafted HTTP POSTs to `/webhooks`.

### Recommendation
In `WebhooksController#verify_signature`, or in each handler, cross-validate that the organization used to select the webhook secret (`repository.owner.login` / `organization.login`) matches the owner portion of `payload.dig('repository','full_name')` before dispatching to handlers, rejecting the request (422) on mismatch. Additionally, treat a `nil`/blank `webhook_secret` as a hard misconfiguration in production (fail closed) rather than `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, using a multi-org secrets fixture like `test/dummy/config/secrets_double_github_app.yml`):
```ruby
test "cross-org pull_request:assigned payload cannot mutate a different org's PullRequest" do
  # Arrange: victim stack/repository under "OrgTwo", real PullRequest with number 2, no assignees
  victim_pr = shipit_pull_requests(:review_stack_review) # belongs to OrgTwo repository
  victim_pr.assignees.clear
  original_assignees = victim_pr.reload.assignees.to_a

  # Attacker crafts payload: repository.full_name points at victim, owner.login is attacker's own org
  payload = payload_parsed(:pull_request_assigned)
  payload["number"] = victim_pr.number
  payload["pull_request"]["number"] = victim_pr.number
  payload["repository"]["full_name"] = victim_pr.stack.repository.github_repo_name # victim-org/victim-repo
  payload["repository"]["owner"] = { "login" => "OrgOne" } # attacker's own configured org, no secret

  @request.headers['X-Github-Event'] = 'pull_request'
  # signature computed/omitted: OrgOne has no webhook_secret configured -> verify_webhook_signature returns true unconditionally

  assert_no_changes -> { victim_pr.reload.assignees.map(&:login) } do
    post :create, body: payload.to_json, as: :json
  end
  # Equality being validated: repository_owner ("OrgOne") used for signature verification
  # MUST equal owner of payload["repository"]["full_name"] ("victim-org") for the write to be legitimate.
  # If assignees changed despite org mismatch, the binding is broken.
end
```
This test should fail (assignees change) against current code, demonstrating the break, and pass once cross-org validation is added.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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
