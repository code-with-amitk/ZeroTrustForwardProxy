# Policy Engine
## Policy format (policy.yaml)
* Policy is set of rules which contains domain, user, action
* ie for particular domain, user. What would be the action
* Policies are evaluated from top to bottom and checked for match

## Flow
* policy.yaml is read into internal DS
```
rules:
  - user: "alice"
    domain: "www.google.com"
    action: allow
```
* Whenever a HTTP Request arrives, domainname(parsed from header), user is parsed from JWT Token
```
GET / HTTP/1.1
Host: example.com
Headers:
	User-Agent: ztfp-client/1.0
	Authorization: Bearer XXXX //example user from token=alice
	Accept-Encoding: gzip
```
* Rules are checked from top to bottom, whenever host=google.com, user=alice is matched, action=Allow is returned

### Action=Allow 
* On action=Allow, request is forwarded to destination server
* Some of fields can be added. As response is recieved from destination server, response is returned to client

### Action=Block
* Request is dropped at proxy and a Coaching message is sent to client

## Evaluation Logic
- Rule matching is first-match-wins.
- `user` can be exact or `*`.
- `domain` supports:
  - exact: `example.com`
  - wildcard suffix: `*.example.com`
  - global wildcard: `*`
- If no rule matches, `default_action` is used.
