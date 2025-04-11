package main

import (
	"fmt"
	"strconv"
	"strings"
)

type RuleFields struct {
	Action   int
	Protocol int
	SrcPort  int
	DstPort  int
	SrcIP    string
	DstIP    string
}

func ConvertToEnums(ActionStr, ProtoStr string) (action, protocol int, err error) {
	switch strings.ToLower(ActionStr) {
	case "accept":
		action = 1
	case "denial":
		action = 0
	default:
		return 0, 0, fmt.Errorf("invalid action value: %q", ActionStr)
	}

	switch strings.ToLower(ProtoStr) {
	case "tcp":
		protocol = 1
	case "udp":
		protocol = 0
	default:
		return 0, 0, fmt.Errorf("invalid protocol value: %q", ProtoStr)
	}

	return action, protocol, nil
}

// ParsePorts converts port strings to integers
func ParsePorts(SrcPortStr, DstPortStr string) (srcPort, dstPort int, err error) {
	srcPort, err = strconv.Atoi(strings.TrimSpace(SrcPortStr))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid source port: %v", err)
	}

	dstPort, err = strconv.Atoi(strings.TrimSpace(DstPortStr))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid destination port: %v", err)
	}

	return srcPort, dstPort, nil
}

func ProcessLine(line string) (*RuleFields, error) {
	line = strings.ReplaceAll(line, " ", "")
	fields := strings.Split(line, ";")
	if len(fields) < 6 {
		return nil, fmt.Errorf("malformed line: insufficient fields")
	}

	// Extract raw values
	actionStr := fields[0]
	protoStr := fields[1]

	srcPortStr := "0"
	stp := strings.Split(fields[2], "=")
	if stp[0] == "sport" {
		srcPortStr = stp[1]
	}

	srcIPStr := ""
	stip := strings.Split(fields[3], "=")
	if stip[0] == "sip" {
		srcIPStr = stip[1]
	}

	dstPortStr := "0"
	dtp := strings.Split(fields[4], "=")
	if dtp[0] == "dport" {
		dstPortStr = dtp[1]
	}

	dstIPStr := ""
	dtip := strings.Split(fields[5], "=")
	if dtip[0] == "dip" {
		dstIPStr = dtip[1]
	}

	// Convert to integers
	action, protocol, err := ConvertToEnums(actionStr, protoStr)
	if err != nil {
		return nil, err
	}

	srcPort, dstPort, err := ParsePorts(srcPortStr, dstPortStr)
	if err != nil {
		return nil, err
	}

	return &RuleFields{
		Action:   action,
		Protocol: protocol,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		SrcIP:    srcIPStr,
		DstIP:    dstIPStr,
	}, nil
}
