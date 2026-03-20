Feature: SNMP trap sending

  Verify that the agent correctly encodes and delivers SNMPv2c traps to a
  real snmptrapd receiver.

  Background:
    Given snmptrapd is running

  @REQ-0034 @REQ-0035 @REQ-0036 @REQ-0037 @REQ-0038 @REQ-0039 @REQ-0041 @REQ-0046 @REQ-0050
  Scenario: Cold-start trap includes mandatory RFC 3416 varbinds
    When the agent sends a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "cold-start"
    And trap "cold-start" has varbind "1.3.6.1.2.1.1.3.0"
    And trap "cold-start" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"

  @REQ-0040
  Scenario: Integer32 varbinds are preserved in transit
    When the agent sends a trap with OID "1.3.6.1.6.3.1.1.5.3" and varbinds:
      | oid                   | type      | value |
      | 1.3.6.1.2.1.2.2.1.1.1 | Integer32 | 1     |
      | 1.3.6.1.2.1.2.2.1.7.1 | Integer32 | 2     |
    Then snmptrapd receives a trap named "link-down"
    And trap "link-down" has varbind "1.3.6.1.2.1.2.2.1.1.1" with value "1"
    And trap "link-down" has varbind "1.3.6.1.2.1.2.2.1.7.1" with value "2"

  @REQ-0040
  Scenario: OctetString varbind is preserved in transit
    When the agent sends a trap with OID "1.3.6.1.6.3.1.1.5.1" and varbinds:
      | oid                | type        | value |
      | 1.3.6.1.2.1.1.1.0 | OctetString | hello |
    Then snmptrapd receives a trap named "trap-with-string"
    And trap "trap-with-string" has varbind "1.3.6.1.2.1.1.1.0"

  @REQ-0035 @REQ-0042 @REQ-0044 @REQ-0045 @REQ-0047
  Scenario: Trap is delivered to multiple destinations
    Given a second snmptrapd named "receiver-2" is running
    When the agent sends to receivers "snmptrapd" and "receiver-2" a trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then snmptrapd receives a trap named "primary"
    And trap "primary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"
    And "receiver-2" receives a trap named "secondary"
    And trap "secondary" has varbind "1.3.6.1.6.3.1.1.4.1.0" with value "1.3.6.1.6.3.1.1.5.1"

  Scenario: Oversized trap is rejected before reaching the receiver
    When the agent sends an oversized trap with OID "1.3.6.1.6.3.1.1.5.1"
    Then the agent reports an error containing "MTU"
    And snmptrapd receives no traps

  @REQ-0043
  Scenario: send_trap with no destinations reports an error without sending
    When the agent sends a trap with OID "1.3.6.1.6.3.1.1.5.1" to no destinations
    Then the agent reports an error containing "empty"
    And snmptrapd receives no traps
