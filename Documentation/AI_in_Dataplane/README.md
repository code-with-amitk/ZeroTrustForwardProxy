

# Why AI needed in Dataplane

## Classic policy fails on these scenarios

### 1. User download file at 2AM.
Example-1
```
IF download_time NOT IN working_hours
    THEN ALERT

Human investigates.
    Ask Justification
```

Example-2: Suppose User is working on important customer case and need file.
```
IF
    Jira ticket = active
AND customer = X
AND user assigned to ticket
AND requested file belongs to customer X
THEN ALLOW

Salesforce
Jira
Email
Customer
User
Time
Location
File
Previous activity
...
```
NOTICE here: you're trying to manually encode human reasoning into thousands of rules. <<<<<<<<<<<<<<<<< AI helps


### 2. DLP cannot detect this
```
min_of_meeting.doc                      //internal-only information that should never leave the company

Reshuffle in strategy, now CompanyX will provide 7% discount to us.
```

Employee says send min_of_meeting.doc to Customer2.
```
CLASSIC POLICY
User authorized?            YES
DLP(any creditcard info)?   NO
File allowed?               YES
Email allowed?              YES
Destination allowed?        YES
                 ↓
               ALLOW
```
How many static rules will you create on DLP.      <<<<<<<<<<<<<<<<< AI helps


### 3. AI-agent example
There is a issue, which employee wants AI agent to fix. Agent can:
```
POLICY ALLOW:
    read repository, read logs
    modify code
    create PR
    send PR review email
```
- While reading logs, agent finds **production database password** > Uses password to access production DB (Unauthorized) due to:
    - Agent was compromised (Some Man in Middle)

Agent has legitimate access to Jira, GitHub, logs, PR. Policy cannot restrict: Whether the agent's actual sequence of actions is in authorized scope.                           <<<<<<<<<<<<<<<<<<<< AI helps
