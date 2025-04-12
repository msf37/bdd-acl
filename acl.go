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
	return GetIntRange(bdd, min, max, offset)
}

func GetIntRange(bdd *rudd.BDD, min, max int, offset int) rudd.Node {
	all := bdd.False()
	dif := min

	for dif <= max {
		r := GetBDDFromInt(bdd, dif, offset)
		all = bdd.Or(all, r)
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
	// And process each octet
	var octets []int
	for i := range 4 {
		if parts[i] == "*" {
			r = bdd.And(r, GetIntRange(bdd, 0, 255, offset+i*10))
		} else {
			num, _ := strconv.Atoi(parts[i])
			octets = append(octets, num)
			r = bdd.And(r, GetBDDFromInt(bdd, num, offset+i*10))
		}
	}

	return r
}

func GetRuleFromLine(bdd *rudd.BDD, rule string) rudd.Node {
	rc, err := ProcessLine(rule)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return bdd.And(bdd.True(),
		GetAction(bdd, rc.Action),                                              //action
		GetProtocol(bdd, rc.Protocol),                                          //protocol
		GetPortRange(bdd, rc.SrcPortMin, rc.SrcPortMax, SourcePortOffset),      //source port
		GetAddress(bdd, rc.SrcIP, SourceIpOffset),                              //source ip
		GetPortRange(bdd, rc.DstPortMin, rc.DstPortMax, DestinationPortOffset), //Destination port
		GetAddress(bdd, rc.DstIP, DestinationIpOffset),                         //Destination ip
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
