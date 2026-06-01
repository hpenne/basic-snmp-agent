Feature: SNMP MIB reads with authNoPriv security over plain TCP

  Verify that the agent correctly handles SNMPv3 requests from net-snmp CLI tools
  when authenticated with HMAC-SHA-256 (authNoPriv security level), and that it
  correctly rejects requests with wrong credentials or mismatched security level.

  Background:
    Given a test-agent-mib-auth instance is running with engine ID "0x80001f8804746573742d6167656e742d61757468"

  @REQ-0074 @REQ-0075 @REQ-0078 @REQ-0079 @REQ-0086 @REQ-0091 @REQ-0100 @REQ-0107
  Scenario: GET with correct authNoPriv credentials succeeds
    When snmpget at authNoPriv with user "authuser" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"

  @REQ-0078 @REQ-0079 @REQ-0100 @REQ-0107
  Scenario: GETNEXT with correct authNoPriv credentials succeeds
    When snmpgetnext at authNoPriv with user "authuser" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0"

  @REQ-0078 @REQ-0079 @REQ-0100 @REQ-0107
  Scenario: GETBULK with correct authNoPriv credentials succeeds
    When snmpbulkget at authNoPriv with user "authuser" and password "authpassword", non-repeaters=0 and max-repetitions=2 queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.3.0"
    And the SNMP response contains OID "1.3.6.1.2.1.1.5.0"

  @REQ-0080 @REQ-0093 @REQ-0094 @REQ-0098 @REQ-0099 @REQ-0100 @REQ-0107
  Scenario: GET without explicit engine ID succeeds after automatic discovery with authNoPriv
    When snmpget at authNoPriv without explicit engine ID with user "authuser" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response contains OID "1.3.6.1.2.1.1.1.0" with string value "basic-snmp-agent test instance"

  @REQ-0100
  Scenario: GET with wrong authentication password is rejected
    When snmpget at authNoPriv with user "authuser" and password "wrongpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0078
  Scenario: GET with unknown user name is rejected
    When snmpget at authNoPriv with user "nobody" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0079
  Scenario: GET at noAuthNoPriv security level is rejected by authNoPriv agent
    When snmpget at noAuthNoPriv with user "authuser" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0130
  Scenario: GET at authPriv security level is rejected by authNoPriv agent
    When snmpget at authPriv with user "authuser", auth password "authpassword", and priv password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP request times out or returns an error

  @REQ-0104
  Scenario: GET with correct authNoPriv credentials but wrong contextEngineID receives Report PDU
    When snmpget at authNoPriv with wrong context engine ID "0x80001f8804776f726f6e67" with user "authuser" and password "authpassword" queries OID "1.3.6.1.2.1.1.1.0" from the agent
    Then the SNMP response is a Report PDU
