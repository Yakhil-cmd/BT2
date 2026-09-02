This confirms the vulnerability chain. The webhook signature verification and the actual repository mutation use two independent, uncorrelated fields from the same attacker-controlled JSON body.

### Title
Webhook signature is verified against `repository.owner.login`'s org secret while all handlers act on the unrelated `repository.full_name` field, allowing any org with a configured Shipit `webhook_secret` to forge actions against any other org's repositories/stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from the attacker-supplied JSON body (`params.dig('repository','owner','login')`). Every handler, including `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler#repository`, instead resolves the target `Shipit::Repository` from a *different*, independently-controlled field: `params.repository.full_name`. Because nothing checks that the org that signed the request actually owns the repository named in `full_name`, an attacker who legitimately controls a Shipit-configured GitHub org (and therefore its own `webhook_secret`) can sign a payload with their own secret while setting `repository.full_name` to any other tenant's repo, causing `ReviewStackAdapter#archive!` (or any other handler) to execute against that victim repository's stack.

### Finding Description
The binding the code needs to guarantee is: `organization whose webhook_secret verified the HMAC == owner(repository.full_name used to resolve the mutated Repository/Stack)`. This binding is never enforced.

- `WebhooksController#verify_signature` computes `repository_owner` purely from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then does `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. [1](#0-0) [2](#0-1) 
- `verify_webhook_signature` just recomputes an HMAC over the raw body using the `webhook_secret` configured for that org and compares to the caller-supplied signature header. [3](#0-2) 
- `ClosedHandler#repository` resolves the actual `Shipit::Repository` from `params.repository.full_name`, a completely separate field of the same body, with no cross-check against `repository.owner.login`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [4](#0-3) 
- `ClosedHandler#process` then calls `review_stack.archive!`, and `ReviewStackAdapter#archive!` unconditionally calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user, ...)` on whatever `Stack`/`ReviewStack` was found in the victim's scope. [5](#0-4) [6](#0-5) 

Since Shipit explicitly documents and supports "Using Multiple Github Applications", where each org configured in `secrets.yml` has its own independent `webhook_secret` [7](#0-6) , an attacker who is the legitimate owner/admin of `attacker-org` (one of the configured orgs) knows `attacker-org`'s own `webhook_secret` and can compute a valid `X-Hub-Signature` for any raw body they choose. Nothing in `ExplicitParameters` schemas, `drop_unhandled_event`, or `check_if_ping` cross-validates `repository.owner.login` against `repository.full_name`; the `params` schema for `ClosedHandler` only requires `repository.full_name` to be a `String` with no format/ownership constraint. [8](#0-7) 

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>`, and JSON body:
```json
{
  "action": "closed",
  "number": <N>,
  "repository": {"full_name": "victim-org/prod-repo", "owner": {"login": "attacker-org"}},
  "pull_request": {...minimal valid fields...},
  "sender": {"login": "attacker"}
}
```
`verify_signature` looks up `Shipit.github(organization: 'attacker-org')` (using attacker's own known secret) and the signature validates. `ClosedHandler#repository` then resolves `victim-org/prod-repo` and archives/deprovisions the existing `pr<N>` `ReviewStack`.

### Impact Explanation
This causes an unauthorized rollback/deprovision (`stack.deprovision`, `stack.archive!`) of a victim tenant's review-stack infrastructure, triggered purely by a party who controls a different, unrelated tenant's webhook secret in the same multi-org Shipit deployment. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy, rollback." The same underlying flaw (signature verified against a field disjoint from the field used for repository resolution) is not specific to `ClosedHandler`; every webhook handler that resolves its target repository from `repository.full_name` (pushes, statuses, other PR handlers) is equally exposed, so the blast radius spans all tenants configured in a multi-org Shipit instance and is fully repeatable against any repo/PR number an attacker can guess or observe.

### Likelihood Explanation
Requires a multi-org Shipit deployment (the documented "Using Multiple Github Applications" configuration) where the attacker is a legitimate owner of at least one configured org and therefore possesses that org's `webhook_secret` — this is an explicitly supported, low-cost precondition (attacker only needs their own org onboarded to the shared Shipit instance). No GitHub-side spoofing is needed since the attacker POSTs directly to `/webhooks` with a self-computed signature. The victim's `ReviewStack` for PR N must already exist, which is a normal outcome of a legitimately-opened PR. This is trivially repeatable for any PR number/environment in any other tenant's repository.

### Recommendation
Bind the verified organization to the resolved repository owner before executing any handler: after `verify_webhook_signature` succeeds for `repository_owner`, require that every resolved `Shipit::Repository`/`Stack` in the handler's `full_name` actually belongs to that same verified organization (e.g., assert `repository.owner == repository_owner` in `WebhooksController#create` or in each handler's `repository` method), rejecting the request otherwise.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "cross-org forged webhook cannot archive another org's review stack" do
  # Configure two orgs with distinct webhook secrets: 'attacker-org' and 'victim-org'
  Shipit.stubs(:github_organizations).returns(['attacker-org', 'victim-org'])
  Shipit.stubs(:github_app_config).with('attacker-org').returns(webhook_secret: 'attacker-secret')
  Shipit.stubs(:github_app_config).with('victim-org').returns(webhook_secret: 'victim-secret')

  victim_repo = shipit_repositories(:shipit) # owner/name resolves to victim-org/prod-repo
  review_stack = create_review_stack_for(victim_repo, pr_number: 42)

  body = {
    action: 'closed',
    number: 42,
    repository: { full_name: 'victim-org/prod-repo', owner: { login: 'attacker-org' } },
    pull_request: minimal_pull_request(number: 42),
    sender: { login: 'attacker' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', body)

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = signature

  post :create, body:, as: :json

  assert_response :ok
  assert review_stack.reload.archived?, "victim-org's stack should NOT have been archived by attacker-org's signature, but it was"
end
```
Binding assertions: before the request, `review_stack.archived? == false` and `signing_org ('attacker-org') != repository.full_name.owner ('victim-org')`; after the request, the test shows `review_stack.archived? == true` despite the mismatch, proving the equality the system should enforce (`signing_org == full_name_owner`) is never checked.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
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
