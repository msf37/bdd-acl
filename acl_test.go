package main

import (
	"os"
	"testing"

	"github.com/dalzilio/rudd"
)

func TestBitToBDD(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test with value 1
	node1 := BitToBDD(bdd, 1, 0)
	if node1 == bdd.False() {
		t.Error("BitToBDD(1) should not return False")
	}

	// Test with value 0
	node0 := BitToBDD(bdd, 0, 0)
	if node0 == bdd.True() {
		t.Error("BitToBDD(0) should not return True")
	}
}

func TestGetAction(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test accept action
	acceptNode := GetAction(bdd, 1)
	if acceptNode == bdd.False() {
		t.Error("GetAction(1) should not return False")
	}

	// Test deny action
	denyNode := GetAction(bdd, 0)
	if denyNode == bdd.True() {
		t.Error("GetAction(0) should not return True")
	}
}

func TestGetProtocol(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test TCP protocol
	tcpNode := GetProtocol(bdd, 1)
	if tcpNode == bdd.False() {
		t.Error("GetProtocol(1) should not return False")
	}

	// Test UDP protocol
	udpNode := GetProtocol(bdd, 0)
	if udpNode == bdd.True() {
		t.Error("GetProtocol(0) should not return True")
	}
}

func TestGetBDDFromInt(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test with value 255 (all bits set)
	node255 := GetBDDFromInt(bdd, 255, 0)
	if node255 == bdd.False() {
		t.Error("GetBDDFromInt(255) should not return False")
	}

	// Test with value 0 (no bits set)
	node0 := GetBDDFromInt(bdd, 0, 0)
	if node0 == bdd.True() {
		t.Error("GetBDDFromInt(0) should not return True")
	}
}

func TestGetPort(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test valid port
	portNode := GetPort(bdd, 80, 0)
	if portNode == bdd.False() {
		t.Error("GetPort(80) should not return False")
	}

	// Test port range
	portRangeNode := GetPortRange(bdd, 80, 443, 0)
	if portRangeNode == bdd.False() {
		t.Error("GetPortRange(80, 443) should not return False")
	}
}

func TestGetAddress(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test specific IP
	ipNode := GetAddress(bdd, "192.168.1.1", 0)
	if ipNode == bdd.False() {
		t.Error("GetAddress(192.168.1.1) should not return False")
	}

	// Test wildcard IP
	wildcardNode := GetAddress(bdd, "192.168.*.*", 0)
	if wildcardNode == bdd.False() {
		t.Error("GetAddress(192.168.*.*) should not return False")
	}
}

func TestGetRuleFromLine(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Test valid rule
	rule := "Accept;TCP;sport=80;sip=192.168.1.1;dport=443;dip=10.0.0.1"
	ruleNode := GetRuleFromLine(bdd, rule)
	if ruleNode == nil {
		t.Error("GetRuleFromLine should not return nil for valid rule")
	}

	// Test invalid rule
	invalidRule := "Invalid;TCP;sport=80;sip=192.168.1.1;dport=443;dip=10.0.0.1"
	invalidNode := GetRuleFromLine(bdd, invalidRule)
	if invalidNode != nil {
		t.Error("GetRuleFromLine should return nil for invalid rule")
	}
}

func TestLoadPolicy(t *testing.T) {
	bdd, err := rudd.New(1e6)
	if err != nil {
		t.Fatalf("Failed to create BDD: %v", err)
	}

	// Create a temporary policy file
	tempFile := "test_policy.txt"
	content := `Accept;TCP;sport=80;sip=192.168.1.1;dport=443;dip=10.0.0.1
Denial;UDP;sport=53;sip=8.8.8.8;dport=53;dip=1.1.1.1`

	err = os.WriteFile(tempFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temporary policy file: %v", err)
	}
	defer os.Remove(tempFile)

	// Test loading policy
	policyNode := LoadPolicy(bdd, tempFile)
	if policyNode == bdd.False() {
		t.Error("LoadPolicy should not return False for valid policy file")
	}
}

func TestProcessLine(t *testing.T) {
	// Test valid rule
	rule := "Accept;TCP;sport=80;sip=192.168.1.1;dport=443;dip=10.0.0.1"
	fields, err := ProcessLine(rule)
	if err != nil {
		t.Errorf("ProcessLine failed for valid rule: %v", err)
	}
	if fields.Action != 1 || fields.Protocol != 1 {
		t.Error("ProcessLine parsed values incorrectly")
	}

	// Test invalid rule
	invalidRule := "Invalid;TCP;sport=80;sip=192.168.1.1;dport=443;dip=10.0.0.1"
	_, err = ProcessLine(invalidRule)
	if err == nil {
		t.Error("ProcessLine should return error for invalid rule")
	}
}

func TestConvertToEnums(t *testing.T) {
	// Test valid action and protocol
	action, protocol, err := ConvertToEnums("Accept", "TCP")
	if err != nil {
		t.Errorf("ConvertToEnums failed for valid input: %v", err)
	}
	if action != 1 || protocol != 1 {
		t.Error("ConvertToEnums returned incorrect values")
	}

	// Test invalid action
	_, _, err = ConvertToEnums("Invalid", "TCP")
	if err == nil {
		t.Error("ConvertToEnums should return error for invalid action")
	}

	// Test invalid protocol
	_, _, err = ConvertToEnums("Accept", "Invalid")
	if err == nil {
		t.Error("ConvertToEnums should return error for invalid protocol")
	}
}

func TestParsePorts(t *testing.T) {
	// Test specific ports
	srcMin, srcMax, dstMin, dstMax, err := ParsePorts("80", "443")
	if err != nil {
		t.Errorf("ParsePorts failed for valid input: %v", err)
	}
	if srcMin != 80 || srcMax != 80 || dstMin != 443 || dstMax != 443 {
		t.Error("ParsePorts returned incorrect values")
	}

	// Test wildcard ports
	srcMin, srcMax, dstMin, dstMax, err = ParsePorts("*", "*")
	if err != nil {
		t.Errorf("ParsePorts failed for wildcard input: %v", err)
	}
	if srcMin != 0 || srcMax != 65535 || dstMin != 0 || dstMax != 65535 {
		t.Error("ParsePorts returned incorrect values for wildcard")
	}

	// Test invalid port
	_, _, _, _, err = ParsePorts("invalid", "443")
	if err == nil {
		t.Error("ParsePorts should return error for invalid port")
	}
}
