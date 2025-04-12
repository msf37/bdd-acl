package main

import (
	"fmt"
	"time"

	"github.com/dalzilio/rudd"
)

func main() {
	// create a new BDD with 6 variables, 10 000 nodes and a cache size of 5 000 (initially),
	// with an implementation based on the BuDDY approach
	bdd, err := rudd.New(1e6)
	if err != nil {
		fmt.Println(err)
		return
	}

	in := GetRuleFromLine(bdd, "Accept;  TCP;  sport=39;  sip=102.52.83.81;  dport= 45;  dip=127.0.0.1")

	policy := LoadPolicy(bdd, "policy.txt")
	s := time.Now()
	fmt.Println(bdd.Equal(bdd.And(policy, in), in))
	fmt.Println(time.Since(s))
}
