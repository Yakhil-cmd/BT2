### Title
Webhook signature verification is fully bypassed when `webhook_secret` is unset, letting an unauthenticated caller select the target repository via an unverified `full_name` field - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as "verification passed" instead of "verification impossible," and the controller that calls it selects *which* GitHub App/secret to check against using one payload field (`repository.owner.login`) while every event handler resolves the actual `Stack`/`Repository` to act on using a *different*, uncorrelated payload field (`repository.full_name`). This breaks the intended binding "signature verified for organization X" == "repository mutated belongs to organization X," and when no secret is configured it removes authentication entirely.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App configuration purely from the untrusted request body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```
`repository_owner` comes straight from the JSON body: [2](#0-1) 

The signature check itself silently no-ops when the resolved app has no configured secret: [3](#0-2) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```

Meanwhile every `Handler` resolves the actual repository/stack that will be mutated from a *different* field of the same untrusted body: [4](#0-3) 

Shipit explicitly supports (and documents) multiple GitHub Apps/organizations, each with its own independent, "optional" `webhook_secret`: [5](#0-4) [6](#0-5) 

Because the two lookups use two different fields, and because `verify_webhook_signature` accepts everything when a secret is absent, the binding "the organization whose signature the platform verified" is never checked against "the repository the request is going to mutate." Concretely, in any deployment where at least one configured organization has no `webhook_secret` (a state the setup docs present as normal/optional, and the default in `test/dummy/config/secrets.yml` and both `secrets_double_github_app.yml` orgs), an attacker with zero credentials can:
1. Set `repository.owner.login` to that unsecured organization's name so `verify_webhook_signature` short-circuits to `true` for any body/signature (including a missing/garbage `X-Hub-Signature`).
2. Set `repository.full_name` to any other, fully unrelated, secured organization's repository that Shipit tracks, so the event handler resolves and mutates a `Stack` under a completely different trust domain.

### Impact Explanation
This allows an unauthenticated attacker to make Shipit treat arbitrary HTTP requests as authentic GitHub events for a repository the attacker has no relationship with, purely by naming that repository in `full_name`. Concretely reachable handlers include:
- `status` handler, which creates a `Status` on an arbitrary commit with `state: success` from spoofed data: [7](#0-6) . `Commit#add_status` then triggers `stack.schedule_merges if new_status.pending? || new_status.success?`: [8](#0-7) , which can push spoofed-green commits into the merge queue - an unauthorized merge.
- `push` handler, which forces `stack.sync_github` for any branch of the targeted stack: [9](#0-8) .

This lands in the "Critical - unauthorized deploy, rollback or merge" impact bucket, since forged CI-success statuses can unblock the merge/deploy pipeline for a repository the attacker never had signature-verified access to.

### Likelihood Explanation
Requires: (a) the target Shipit deployment to configure multiple GitHub organizations (a documented, supported configuration), and (b) at least one of those organizations to have `webhook_secret` unset (explicitly documented as "optional," and the default shown in every secrets template/fixture in this repo). Given that combination — which involves no leaked secret, no session, no repository write access, and no privileged account — the exploit is a single unauthenticated HTTP POST to `/webhooks`.

### Recommendation
- Change `verify_webhook_signature` to fail closed: a missing/blank `webhook_secret` should never be treated as "verified"; either require `webhook_secret` for every configured organization, or refuse to process events for apps without one.
- Do not select the verification secret from an unauthenticated payload field, then act on a different unauthenticated payload field. After signature verification succeeds, cross-check that the organization whose secret verified the signature actually matches the owner of the repository named in `repository.full_name` before dispatching to handlers.

### Proof of Concept
Given a `config/secrets.yml` with two GitHub Apps, e.g.:
```yaml
github:
  UnsecuredOrg:
    webhook_secret: # left blank, as documented "optional"
    ...
  VictimOrg:
    webhook_secret: some-real-secret
    ...
```
An unauthenticated attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=deadbeef   (arbitrary/garbage)
Content-Type: application/json

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "UnsecuredOrg" }, "full_name": "VictimOrg/victim-repo" }
}
```
`verify_signature` resolves `Shipit.github(organization: "UnsecuredOrg")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`). `StatusHandler#process` then looks up `Commit.where(sha: ...)` and marks it successful, while `PushHandler`/others resolve the affected `Stack` via `repository.full_name == "VictimOrg/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), fully decoupled from the `UnsecuredOrg` identity that was actually "verified."

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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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
