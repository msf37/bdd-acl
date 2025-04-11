package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dalzilio/rudd"
)

const (
	ProtocolOffset        = 1
	ActionOffset          = 20
	SourcePortOffset      = 50
	DestinationPortOffset = 150
	SourceIpOffset        = 300
	DestinationIpOffset   = 500
)

func BitToBDD(bdd *rudd.BDD, v int, offset int) rudd.Node {
	if v == 1 {
		return bdd.Ithvar(offset)
	}
	return bdd.NIthvar(offset)
}

func GetAction(bdd *rudd.BDD, action int) rudd.Node {
	r := bdd.True()

	r = bdd.And(r, BitToBDD(bdd, action, ActionOffset))

	return r
}

func GetProtocol(bdd *rudd.BDD, protocol int) rudd.Node {
	r := bdd.True()

	r = bdd.And(r, BitToBDD(bdd, protocol, ProtocolOffset))
	return r
}

// convert the number which is 8 bit from 0 to 255
func GetBDDFromInt(bdd *rudd.BDD, value int, offset int) rudd.Node {
	var array = []int{0, 0, 0, 0, 0, 0, 0, 0}
	for i := range 8 {
		array[i] = 0
		if value&(1<<i) != 0 {
			array[i] = 1
		}
	}
	r := bdd.True()
	for i, item := range array {
		r = bdd.And(r, BitToBDD(bdd, item, offset+i))
	}
	return r
}

// convert the port which is 8 bit from 0 to 255
func GetPort(bdd *rudd.BDD, port int, offset int) rudd.Node {
	return GetBDDFromInt(bdd, port, offset)
}

func GetPortRange(bdd *rudd.BDD, min, max int, offset int) rudd.Node {
	all := bdd.False()
	dif := min

	for dif <= max {
		r := GetPort(bdd, dif, offset)
		all = bdd.Apply(all, r, rudd.OPor)
		dif++
	}
	return all
}

func GetAddress(bdd *rudd.BDD, ip string, offset int) rudd.Node {
	// Initialize result
	r := bdd.True()

	// Split IP address into octets
	parts := strings.Split(ip, ".")

	// Convert each octet to integer
	var octets []int
	for _, part := range parts {
		num, _ := strconv.Atoi(part)
		octets = append(octets, num)
	}
	// Process each octet
	r = bdd.And(r, GetBDDFromInt(bdd, octets[3], offset))
	r = bdd.And(r, GetBDDFromInt(bdd, octets[2], offset+10)) //offset by 8bit for each octet
	r = bdd.And(r, GetBDDFromInt(bdd, octets[1], offset+20))
	r = bdd.And(r, GetBDDFromInt(bdd, octets[0], offset+30))

	return r
}

func GetRuleFromLine(bdd *rudd.BDD, rule string) rudd.Node {
	rc, err := ProcessLine(rule)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return bdd.And(bdd.True(),
		GetAction(bdd, rc.Action),                       //action
		GetProtocol(bdd, rc.Protocol),                   //protocol
		GetPort(bdd, rc.SrcPort, SourcePortOffset),      //source port
		GetAddress(bdd, rc.SrcIP, SourceIpOffset),       //source ip
		GetPort(bdd, rc.DstPort, DestinationPortOffset), //Destination port
		GetAddress(bdd, rc.DstIP, DestinationIpOffset),  //Destination ip
	)
}

func LoadPolicy(bdd *rudd.BDD, filename string) rudd.Node {
	policy := bdd.False()
	restRules := bdd.True()

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			currRule := GetRuleFromLine(bdd, line)
			policy = bdd.Or(policy, bdd.And(restRules, currRule)) /*policy = !R1 & !R2 & R3   : where (!R1 & !R2) is restRules and R3 is currRule*/
			restRules = bdd.And(restRules, bdd.Not(currRule))     /*add the current rule to the reset sence its the rest for the next rule(R4)*/
		}
	}
	return policy
}
