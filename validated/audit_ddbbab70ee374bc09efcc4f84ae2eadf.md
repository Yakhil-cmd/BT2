### Title
Webhook signature verification is bypassed for GitHub organizations with no `webhook_secret`, allowing forged unsigned webhooks to write to any repository's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
The analog to the "wrong amount stored because the value used was never the one that was actually validated" bug class is a binding failure between **the organization whose signature is checked** and **the repository/organization the webhook payload is actually applied to**. `WebhooksController#verify_signature` derives the signing organization directly from the untrusted payload and, for any org configured with a blank `webhook_secret`, skips HMAC verification entirely — yet the very same untrusted payload is what handlers use to write Teams, Stacks, commit statuses and check-run refreshes.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to check the signature against using a value read straight out of the unauthenticated request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` then unconditionally accepts the request if that organization has no configured secret: [3](#0-2) 

Multi-app deployments commonly leave `webhook_secret` unset for some orgs (`webhook_secret: # nil` in the documented multi-org config, and `"webhook_secret": null` in the test fixtures): [4](#0-3) [5](#0-4) 

Because `repository_owner` is attacker-controlled and independent from the org whose repositories are actually acted upon, an attacker can set `repository.owner.login` (or `organization.login`) to any org that has no `webhook_secret` configured to make `verify_signature` pass with `head(422) unless verified` never firing, while the payload's other fields (`repository.full_name`, `sha`, `check_suite`, `team`, `member`) are handled at face value by the downstream handlers — e.g. `PushHandler#process`, `StatusHandler#process`, `CheckSuiteHandler#process`, `MembershipHandler#process`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

The binding that is broken is: `organization authenticated by verify_signature == organization/repository whose data is written by the handler`. In truth, the field used to select the verification secret and the fields used to perform the write are both taken from the same unauthenticated JSON body, so the "authentication" only proves the attacker knows (or doesn't need to know) the secret of whatever org name they chose to put in the payload — not that the org/repository actually targeted by the write is the same one.

`MembershipHandler` is the most sensitive case: it creates/updates a `Team` scoped by `params.organization.login` and adds/removes a `User` (`params.member.login`) from it based purely on the forged, unsigned payload: [10](#0-9) 
If that team/org is one referenced by `Shipit.github_teams` (used elsewhere for OAuth authorization), an attacker can forge a `membership` webhook naming an org with a blank `webhook_secret`, adding an arbitrary GitHub login (including their own) into a team that the app treats as authorized, without ever presenting a valid webhook signature.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out as in-scope, and lands in the High-severity bucket: escalation into `Shipit.github_teams` authorization via forged, unsigned `membership` webhooks, plus unauthenticated manipulation of commit statuses / check-run state that can influence `deployable_status`/`merge_status` for stacks belonging to orgs unrelated to the one whose blank secret was abused to pass verification.

### Likelihood Explanation
Exploitability depends entirely on the deployment's `config/secrets.yml`: it requires that at least one configured GitHub organization has a blank/unset `webhook_secret`. This is explicitly shown as a supported/valid configuration in the shipped documentation and default templates, and the app does not require all orgs to have a secret configured. In multi-organization Shipit deployments this is a realistic operator configuration, since the docs simply describe setting the secret as optional guidance rather than mandatory.

### Recommendation
Never allow a blank/unset `webhook_secret` to short-circuit signature verification. `GitHubApp#verify_webhook_signature` should fail closed (reject) when no secret is configured for an org, or the application should require a non-blank `webhook_secret` for every configured GitHub organization at boot time. Additionally, handlers should validate that the repository/organization actually being written to belongs to the same organization used to select the verification secret, rather than trusting `repository.full_name`, `organization.login`, or `team`/`member` fields taken at face value from the same unauthenticated body used to pick the verification key.

### Proof of Concept
1. Configure (or find) a Shipit deployment with two GitHub orgs: `org-protected` (has `webhook_secret` set) and `org-empty` (no `webhook_secret`, e.g. per the shipped `config/secrets.development.shopify.yml` template) [4](#0-3) .
2. POST to `/webhooks` with header `X-Github-Event: membership` and a body where `organization.login = "org-empty"` but naming a `team` that Shipit's `Shipit.github_teams` authorization actually trusts, and `member.login` set to the attacker's own GitHub username.
3. `WebhooksController#repository_owner` resolves to `"org-empty"`; `Shipit.github(organization: "org-empty")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of any (or no) `X-Hub-Signature` header [3](#0-2) .
4. `MembershipHandler#process` adds the attacker's `User` to the trusted `Team` [10](#0-9) , granting them team-based authorization without any legitimate GitHub webhook ever having been sent.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** test/dummy/config/secrets.test.json (L7-13)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
