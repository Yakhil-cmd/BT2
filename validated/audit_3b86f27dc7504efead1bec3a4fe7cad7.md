### Title
Webhook authentication bypass when `webhook_secret` is unset - forged GitHub events accepted (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for an organization, with no distinction between "secret intentionally disabled" and "secret missing/blank." Combined with `WebhooksController#verify_signature` picking which organization's (and therefore which secret's) verification context to use from an **unverified** field of the same untrusted payload, an unprivileged network attacker can post arbitrary, unsigned webhook bodies that are accepted as authentic GitHub events for any configured organization whose `webhook_secret` is blank.

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App/secret to check against using a field read straight out of the still-unverified JSON body: [1](#0-0) [2](#0-1) 

The actual cryptographic check is: [3](#0-2) 

`return true unless webhook_secret` means: if the resolved organization's `webhook_secret` is `nil`/blank, **any** payload — with **any or no** `X-Hub-Signature` header — is treated as verified, exactly mirroring the reported bug class (`AggregatePublicKeys` returning a "verified" result with no length/presence check on its input). Here the "signature" check trivially passes when the expected secret is absent, rather than rejecting or requiring a secret.

This is not a hypothetical edge case: the shipped example configs explicitly document `webhook_secret` as optional and default it to blank — [4](#0-3) [5](#0-4) 
— and Shipit explicitly supports multiple GitHub Apps per organization, each with its own independently-configured secret: [6](#0-5) 

So a Shipit instance that authenticates deploys/merges from a "hard" org (secret set) can simultaneously have a second configured org left with a blank secret (e.g. mis-copied template, or an org added later without immediately setting a secret). Any request whose `repository.owner.login` (or `organization.login`) resolves to that blank-secret org bypasses verification entirely, regardless of signature.

### Impact Explanation
Once `verify_signature` passes, the raw JSON is dispatched to handlers keyed only by the `X-Github-Event` header and processed on the unverified body content, e.g.: [7](#0-6) [8](#0-7) 

An attacker can forge `status` events to set arbitrary commit CI state (e.g., mark a malicious/unreviewed commit as `success` for any tracked repository under the affected organization), or forge `push`/`check_suite`/`membership` events, influencing Shipit's deploy-readiness signals and repository/team membership records — i.e., an unauthorized deploy pathway, matching the "unauthorized deploy" Critical-impact category in scope.

### Likelihood Explanation
Requires only that one configured organization in a multi-org Shipit deployment has a blank `webhook_secret` — a state the project's own example configuration and docs actively produce (`webhook_secret: # nil`) and call "optional." No credentials, session, or repository access are needed; the attacker only needs network access to the `/webhooks` endpoint and knowledge (or guessing) of the affected organization/repository name in the payload.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub App/organization; fail closed (return `false`/`422`) instead of `true` when it is missing.
- Do not select the verification key from unverified payload fields before any cryptographic check has succeeded; verify against every configured secret, or reject if the resolved org has no secret, rather than treating "no secret" as "always verified."
- Emit a startup/runtime warning (or refuse to boot) if any configured GitHub App lacks a `webhook_secret`.

### Proof of Concept
1. Configure Shipit (as `docs/setup.md` shows is valid) with two orgs: `OrgA` (has `webhook_secret: set`) and `OrgB` (`webhook_secret:` left blank, per the shipped example).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: status` and no/garbage `X-Hub-Signature`, with body:
```json
{"sha":"<victim-commit-sha>","state":"success","repository":{"owner":{"login":"OrgB"},"full_name":"OrgB/some-tracked-repo"}}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank — [9](#0-8) 
— and `StatusHandler` marks the given commit's CI status as `success` with no authentication ever having been checked.

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
