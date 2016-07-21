package cidrtree

import (
	"fmt"
	"sort"
)

// CIDRTree is a tree of nodes connected by edges that contain cidr IPs and associated data
type CIDRTree struct {
	root  *node
	nodes []*node
	cidrs int
}

// NewCIDRTree returns a pointer to a new tree with a root node
func NewCIDRTree() *CIDRTree {
	var ns []*node
	root := &node{outgoing: make([]edge, 0)}
	ns = append(ns, root)
	return &CIDRTree{nodes: ns, root: root}

}

type node struct {
	data     string
	outgoing []edge
}

// If the oectet does not yet exist, return pointer to a new node with an outgoing edge with the given octet
func (n *node) createNext(octet byte, data string) *node {
	next := n.findNext(octet)
	if next != nil {
		// The edge already exists
		return nil
	}
	// Otherwise register new node and edge
	next = &node{data: data}
	n.outgoing = append(n.outgoing, edge{next: next, octet: octet})
	return next
}

func (n *node) findNext(octet byte) *node {
	for _, edge := range n.outgoing {
		if edge.octet == octet {
			return edge.next
		}
	}
	return nil
}

// Perform a binary search for a given alpha among the outgoing edges of a node
func (n *node) binarySearchNext(octet byte) *node {
	i := sort.Search(len(n.outgoing), func(i int) bool { return n.outgoing[i].octet >= octet })
	if i < len(n.outgoing) && n.outgoing[i].octet == octet {
		// octet was found
		return n.outgoing[i].next
	}
	return nil
}

type edge struct {
	octet byte
	next  *node
}

type sortable []edge

func (s sortable) Len() int           { return len(s) }
func (s sortable) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s sortable) Less(i, j int) bool { return s[i].octet < s[j].octet }

// AddIPData inserts an IP address in the CIDR tree with some associated data
func (t *CIDRTree) AddIPData(ip []byte, data string) {
	n := t.root
	var next *node
	for _, octet := range ip {
		next = n.findNext(octet)
		if next != nil {
			n = next
			continue
		} else {
			// The octet was not found, create a node that leads to it
			next = n.createNext(octet, data)
			sort.Sort(sortable(n.outgoing))
			n = next
		}
		t.cidrs++
	}
}

// Size returns the number of CIDR adresses stored in the tree
func (t CIDRTree) Size() int {
	return t.cidrs
}

// FindDataByIP takes an IP and tries to find the CIDR it belongs to. If found, the data of the appropriate CIDR is returned.
func (t *CIDRTree) FindDataByIP(ip []byte) (string, error) {
	var current *node
	var next *node
	current = t.root

	// Search for the string in text, character by character
	for i, octet := range ip {
		next = current.binarySearchNext(octet)
		if next == nil {
			// Exact match not found, look in outgoing edges
			if len(current.outgoing) == 0 {
				return "", fmt.Errorf("Not found")
			}

			biggerThan := -1
			smallerThan := -1
			for j, edge := range current.outgoing {
				if octet >= edge.octet {
					biggerThan = j
				} else {
					smallerThan = j
				}

				if biggerThan < smallerThan {
					return current.outgoing[biggerThan].next.data, nil
				}
			}
			// There are no more octets to compare to, so the IP belongs to the last octet
			if smallerThan == -1 {
				return current.outgoing[biggerThan].next.data, nil
			}

			// No fitting octet
			return "", fmt.Errorf("Not found")
		}
		current = next

		if i == 3 && next != nil {
			return current.data, nil
		}
	}

	return "", fmt.Errorf("Not found")
}
