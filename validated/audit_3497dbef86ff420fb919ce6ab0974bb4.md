### Title
Webhook signature is verified against the organization derived from an unauthenticated payload field, while dispatch writes to a different, attacker-controlled repository — allowing cross-organization webhook forgery (`app/controllers/shipit/webhooks_controller.rb`)

### Finding Description
This engine's webhook entry point authenticates a request by picking which GitHub App/organization secret to verify against using a field taken directly from the **unauthenticated JSON body**, then dispatches the write using a **different** field from that same unauthenticated body. Specifically:

- `WebhooksController#verify_signature` selects the app config with `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — attacker-controlled JSON, not covered by any signature at the time it is read. [1](#0-0) [2](#0-1) 

- Every `Handler` subclass, however, determines which repository/stack actually gets mutated using an independent field, `repository_name = payload.dig('repository', 'full_name')`. [3](#0-2) 

Shipit explicitly supports hosting multiple, independently-secreted GitHub organizations on one instance (`Shipit.github_app_config`, `Shipit.github_organizations`), each with its own `webhook_secret`. [4](#0-3) [5](#0-4) 

`GitHubApp#verify_webhook_signature` additionally returns `true` unconditionally whenever an organization's `webhook_secret` is blank — a state shown as the literal default in the shipped example configs. [6](#0-5) [7](#0-6) 

Because the field used to select the verifying secret (`repository.owner.login`) is never bound to the field used to select the write target (`repository.full_name`), an attacker can pick an organization on the same instance that has no `webhook_secret` (or one whose secret they can obtain, e.g. as its GitHub org owner) and put that org's login in `repository.owner.login` while pointing `repository.full_name` at a completely unrelated organization's repository/stack. Verification passes against the harmless org, and the handler operates on the target org's data — breaking the binding "organization that authenticated" == "repository that is written."

### Impact Explanation
This is a cross-organization authentication bypass leading to cross-repository writes without any GitHub App credential, Shipit session, or API token:
- `PushHandler#process` uses `repository_name` from the same forged payload to look up stacks and calls `stack.sync_github(expected_head_sha: params.after)` — allowing an attacker to drive sync of an arbitrary commit SHA into a victim stack they don't own. [8](#0-7) 
- `StatusHandler#process` calls `commit.create_status_from_github!(params)` for any commit matching the forged `sha`; this can flip a commit's status which in turn calls `stack.schedule_merges` when the new status is `success`, and status checks gate the merge queue's `reject_unless_mergeable!`/`any_status_checks_failed?` logic used by `MergeRequest#merge!`. [9](#0-8) [10](#0-9) [11](#0-10) 

Combined, this lets an unprivileged attacker (who only needs to be an org owner of any org configured on the shared instance, or to know that some configured org has a blank `webhook_secret`) forge fake green CI status and push events for a repository they do not control, enabling an unauthorized merge and deploy — satisfying the "unauthorized deploy, rollback or merge" / "cross-repository writes" Critical bar.

### Likelihood Explanation
Multi-organization Shipit deployments are a documented, supported configuration (`docs/setup.md`), and the example/default secrets files ship `webhook_secret: # nil` as the baseline value, making an unsecured org a realistic misconfiguration rather than a contrived edge case. No GitHub App private key, `GITHUB_TOKEN`, or Shipit session is required — only the ability to POST an HTTP request to the public webhook endpoint with a crafted JSON body.

### Recommendation
Bind signature verification to the same repository/organization identity that the handlers use to select their write target: verify the signature using the organization that owns `repository.full_name` (not a separately-trusted field), and cross-check that `repository.owner.login` actually matches the owner of that `full_name`/stack before dispatching to handlers. Reject payloads where these two derived identities disagree, and consider disallowing organizations with a blank `webhook_secret` from being treated as universally valid over other orgs' payload namespace.

### Proof of Concept
1. Shipit instance is configured with two organizations, `OrgA` (no `webhook_secret` set, matching the shipped example config) and `victim-org` (properly secured, hosts `victim-org/victim-repo`).
2. Attacker (needs no credentials for `victim-org`) sends:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`; since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`.
4. `PushHandler#process` reads `repository.full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — a write the attacker was never authorized to trigger.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-23)
```ruby
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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

**File:** app/models/shipit/merge_request.rb (L155-167)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?
```
