# SOC-LAB-003 Correlation Validation

## Objective
Detect a five-stage suspicious account activity sequence within
30 minutes while evaluating correlation accuracy.

## Completed Azure-executed testing
- Original regression scenarios: 4 passed
- Repeated-event edge cases: 3 passed
- Session-aware candidate: 2 passed
- Total automated regression assertions: 9 passed

## Confirmed limitation
The original grouping uses CorrelationId, UserId, and SourceIP.
The synthetic mixed-session test demonstrated that events from
separate sessions sharing grouping values can produce a match.

## Candidate mitigation
A session-aware test grouped activity by Scenario and SessionId.
It correctly separated the tested mixed-session sequence.

## Important tradeoff
Real attacks can span sessions. Requiring a single session for
every event could create false negatives.

## Production-readiness gaps
- Existing SOCSecurityEvents_CL schema has no dedicated SessionId
- Correlation ID provenance and uniqueness require validation
- Cross-session attack scenarios require additional regression tests
- Live rule behavior has not been validated for this detection
- Alert thresholds, suppression, and false-positive rates need tuning

## Safety status
SOC-LAB-003 remains disabled with incident creation disabled.
No production-readiness claim is made.
