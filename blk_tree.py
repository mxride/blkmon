"""blk_tree: Provide a Balanced Binary Search to determine the ASN for a IP

*** Purpose ***

A public routeserver is used to list all the subnets in all the BGP AS being
monitored for Hostile IPs.

This module organizes the subnet data into a Balanced Binary Search Tree to
facilitate the determination whether a given IP is in one of the target ASNs.

Since the blocklists can produce a list of thousands of hostile IPs, something
more efficient than basic a "whois" lookup was required.

** Algorithm **

The following class is an implementation of a balanced Binary tree.

cf Balance Binary Search Tree in Python David Cortesi
http://snippets.dzone.com/posts/show/12811

The dzone code is public source, and does not appear to have any specific
license.

The code snippet has been modified in order to input Google ipaddr objects
representing IP subnets into a balanced binary tree structure.

(subnet, AS) pairs are input into the tree structure. In terms of
the actual code:
    binary tree key == subnet represented as a Google ipaddr object
    binary tree value == subnet's AS #


A lookup of the IP address provides the corresponding AS in an efficient manner
in order to determine IP - AS correlation.

The original code snippet used ordinary arithmetic comparisons. The code was
modified to use google's ipaddr fn overloading:
    IP being tested < ipaddr subnet object means "IP addr is less than the
    beginning subnet address
    
    IP being tested > ipaddr subnet object means "IP addr being tested is
    greater than the highest subnet address"
    
    IP being tested == ipaddr subnet object means "IP being tested is contained
    in the subnet"
    
As mentioned above, the ASN is kept along with each subnet object. If an IP addr
falls in one of the subnets, then the corresponding ASN is easily determined.

*** Classes ***

bbsnode         object representing a single node in the binary tree
bbstree         Object representing the binary tree (composed of 0 or more
                nodes)
                
*** Methods ***

lookup(k)       Searches tree for a node with key k.
		        Returns the bbsnode with key k, or None if k is not found.

forward()       Generator that returns each tree node in ascending key order.

reverse()       Generator that returns each tree node in descending key order.

height()        Returns the height of the tree, 0 for the empty tree.
        		The expected search length is height, the maximum is height+2.

insert(k, v=None) Creates a node with key=k, value=v and inserts it into tree

instest(k, v=None) Looks for a node k in the tree. Inserts it only if it does
                not exist. Returns the node.
                
delete(k)       Deletes the tree node with key k if it exists, and rebalances
                the tree as necessary. 

chk_ip(my_ip)   Searches tree for a node with key k where my_ip is in subnet k.
		        Returns the bbsnode with key k, or None if k is not found.
"""

#####
# imports
#####

import cfg
from twisted.python import log

######
#   Google's ipaddr fns - used for treating routeserver output
######
"""
From the Google code source README file:
    ipaddr.py is a library for working with IP addresses, both IPv4 and IPv6.
    It was developed by Google for internal use, and is now open source.

    Project home page: http://code.google.com/p/ipaddr-py/

Google's code is licensed under Apache License 2.0.
cf http://www.apache.org/licenses/LICENSE-2.0
"""

from ipaddr import IPAddress, IPNetwork, collapse_address_list


"""
(David Cortesi's notes concerning the Balanced Binary Tree follow:)

updated 01/06/11 to simplify empty tree definition
Module for balanced binary search trees. Usage:
	from bbst import *
	defines two classes, bbstree and bbsnode.
	
	tree = bbstree() creates a new, empty tree.

	tnode = tree.lookup(k) searches tree for a node with key k.
		Returns the bbsnode with key k, or None if k is not found.
		tnode.key, tnode.value are usable attributes when found.

	tree.forward() is a generator that returns each tree node
		in ascending key order.
	tree.reverse() is a generator that returns each tree node
		in descending key order.
			for tnode in tree.forward/reverse():
				print(tnode.key, tnode.value)

	tree.height() returns the height of the tree, 0 for the empty tree.
		The tree's population is between 2**height and 2**(height+1),
		that is, if height is 7, the tree has from 128 to 255 nodes.
		The expected search length is height, the maximum is height+2.

	tree.insert(k, v=None) creates a node with key=k and value=v
		and inserts it into tree. If a node with key=k already
		exists, its value is updated to v. Nothing is returned.

	tree.instest(k, v=None) looks for a node k in the tree, and inserts
		it only if it does not exist. Returns the node. Use this for
		example if you are using the tree to keep a tally of items k:
		tree.instest(k,0) installs node k only if it didn't exist, but
		returns it, so tree.instest(k,0).value += 1 keeps a tally.
		
	tree.delete(k) deletes the tree node with key k if it exists, and
	        rebalances the tree as necessary.
	
Any data type may be used for a key (not just integers). However, during
lookup, insert, and delete, the key k may be compared to any node's key.
Thus all keys must support ==, >, and < comparisons and be mutually
comparable by Python type rules.

The value of a node may be any Python type. To associate a value with
a key, present it as v in insert(k,v) or instest(k,v). To retrieve a
value, access tree.lookup(k).value or tree.instest(k,v).value. To change
the value of an existing key, assign to tree.lookup(k).value or to
tree.instest(k,v).value, or simply call tree.insert(k,newvalue)

The tree is balanced; adding and deleting keys in any sequence will
not produce an unbalanced tree. The algorithms are based on the
discussion by Julienne Walker found at

http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_andersson.aspx

L Gordon 2012-4-27
Added rtn to check if a single IP address is in one of the subnets in
the tree.

    tree.chk_ip(my_ip searches tree for a node with key k where
        my_ip is in subnet k.
		Returns the bbsnode with key k, or None if k is not found.
		tnode.key, tnode.value are usable attributes when found.
		"value" for our implementation is AS # for the subnet.
"""
#
# A "node" is an object containing a key, a value, a level, and
# links to at most two other nodes.
#
# Walker's algorithms expect the subtrees of any leaf node to be filled
# with pointers to a nil node that acts as a sentinel. It has level=0
# and left and right subs that point to itself. Here we create that one
# node in the bbst module namespace.
#
class bbsnode_0:
	def __init__(self):
		self.level = 0
		self.key = None
		self.value = None
		self.subs = [None,None]
#
NIL_NODE = bbsnode_0()
NIL_NODE.subs = [NIL_NODE,NIL_NODE]
#
# Here we create an official object of type node, with subtrees initialized
# to NIL_NODE:
#
class bbsnode:
	def __init__(self,k,v=None):
		self.level = 1
		self.key = k
		self.value = v
		self.subs = [NIL_NODE,NIL_NODE]
#
# End of class bbsnode.
#
class bbstree:
#
# A "tree" is an object that contains zero or more "nodes." The tree,
# which is the "self" argument to all these member functions, is not
# itself a node, but rather contains nodes, or actually, links to the
# one node which is currently the root of the tree. That in turn links
# to sub-nodes and they to sub-sub-nodes etc.
#
# Here we initialize a new tree. Its only node is NIL_NODE which has
# a level of 0, hence the height of an empty tree is 0.
#
	def __init__(self):
		self.root = NIL_NODE # the tree is empty
		self.lastinsert = None # save last-inserted node
#
# Height
#
	def height(self):
		return self.root.level

#
# Look for key k in the tree; if found, return its node, else return None.
# tree.lookup() is the "public" method; it handles the special case of
# the empty tree. We use __lookup() to recurse into the tree.
#
	def lookup(self, k):
		if self.root != NIL_NODE: # we are not an empty tree
			return self.__lookup(self.root, k)
		else: # this tree has no nodes
			return None # not found
#
# Recursive lookup
#
	def __lookup(self, tnode, k):
		if tnode.key == k:
			return tnode
		else:
			sub = tnode.subs[k > tnode.key] # k is in left or right?
			if sub != NIL_NODE: # we have a subtree that side
				return self.__lookup(sub, k)
			else:
				return None
				
#
# Special lookup fn for single IP address
#
	def chk_ip(self, my_ip):
		if self.root != NIL_NODE: # we are not an empty tree
			return self.__chk_ip(self.root, my_ip)
		else: # this tree has no nodes
			return None # not found
#
# Recursive lookup
#
	def __chk_ip(self, tnode, my_ip):
		if IPNetwork(my_ip) in tnode.key:
			return tnode
		else:
			sub = tnode.subs[IPNetwork(my_ip) > tnode.key] # k is in left or right?
			if sub != NIL_NODE: # we have a subtree that side
				return self.__chk_ip(sub, my_ip)
			else:
				return None


#
# Generator functions, forward() for stepping through the tree in order, and
# reverse() backwards. Self is a tree object, and the generator really needs to
# operate on the tree nodes, so the real generator is __scan. To scan forward,
# one goes first down the left (0) side then down the right (1) side. To scan
# backward, the reverse. Since the code is the same except for the subscripts
# of tnode.subs[], those numbers are passed in as arguments to __scan().
# The scanning function is not recursive as this would be awkward for a python
# generator (yes you can have recursive generators but a generator that calls
# itself only returns another generator object!). It emulates recursion with a
# stack. Stack size is not an issue with a balanced tree; if we stack 31
# tnodes we have a tree of 2 giga-nodes and stack size is not our main issue!
# An empty tree has self.root = NIL_NODE, terminating the generator immediately.
#
	def forward(self):
		return self.__scan(self.root,0,1)

	def reverse(self):
		return self.__scan(self.root,1,0)

	def __scan(self,tnode,first,second):
		direction = 0
		stack = [NIL_NODE] # when popped, ends the loop
		while tnode != NIL_NODE:
			if direction == 0:
				while tnode.subs[first] != NIL_NODE:
					stack.append(tnode)
					tnode = tnode.subs[first]
			yield tnode
			if tnode.subs[second] != NIL_NODE:
				tnode = tnode.subs[second]
				direction = 0
			else:
				tnode = stack.pop()
				direction = 1

#
# The following are sub-functions of __insert, used to balance the tree.
# One basic operation is the skew: "A skew removes left horizontal links by 
# rotating right at the parent." In the example, a/b/c/d/e are key values
# and the digits are level values. Skew(node-with-d):
#
#             d,2               b,2
#            /   \             /   \
#         b,2     e,1  -->  a,1     d,2
#        /   \                     /   \
#     a,1     c,1               c,1     e,1
#
# The following is Walker's non-recursive skew. Although it gets a self
# arg by virtue of being a class attribute of tree, "self" (the tree object)
# is ignored. The function operates only on the argument (a node) t.
#
	def __skew(self, t):
		if t.level != 0: 
			if t.subs[0].level == t.level:
				tmp = t.subs[0]
				t.subs[0] = tmp.subs[1]
				tmp.subs[1] = t
				t = tmp
		return t
#
# The second basic operation is the split: "A split removes consecutive
# horizontal links by rotating left and increasing the level of the parent."
# Continuing the example following the above skew, split(node-with-b)
#
#         b,2                     d,3
#        /   \                   /   \
#     a,1     d,2     -->     b,2     e,2
#            /   \           /   \
#         c,1     e,2     a,1     c,1
#
# The following is Walker's non-recursive split. Again self (a tree) is ignored.
#
	def __split(self, t):
		if t.level != 0:
			if t.level == t.subs[1].subs[1].level:
				tmp = t.subs[1]
				t.subs[1] = tmp.subs[0]
				tmp.subs[0] = t
				t = tmp
				t.level += 1
		return t
#
# With that, we can insert key k into the tree (or simply find it, if
# it already exists). Nothing is returned. As with tree.lookup(),
# tree.insert() is the public method and handles the special case of
# the empty tree; then __insert() is called to do the recursion.
#
	def insert(self, k, v=None):
		if self.root != NIL_NODE: # we are not an empty tree
			self.root = self.__split( self.__skew( self.__insert(self.root, k, v) ) )
		else: # empty tree getting its first node
			self.root = bbsnode(k,v)
			self.lastinsert = self.root
#
# Recursive insertion
#
	def __insert(self, tnode, k, v):
		if k == tnode.key: # key exists, update value
			tnode.value = v
		else: # it goes in the left or the right
			side = k > tnode.key
			sub = tnode.subs[ side ]
			if sub != NIL_NODE: # there is a subtree that side
				tnode.subs[side] = self.__split( self.__skew( self.__insert(sub, k, v) ) )
			else: # no subtree on that side, make new leaf
				self.lastinsert = bbsnode(k,v)
				tnode.subs[side] = self.lastinsert
		return tnode
#
# Because of balancing, it is impractical for insert() to return the inserted 
# node: __insert() may return a different node as a result of balancing, and
# insert() doesn't know if self.lastinsert was updated or not. This makes it
# awkward to use the tree e.g. to keep a running tally of input symbols, where
# each symbol is stored as a key and the tally is the value. Here we provide
# instest() for this purpose: it can know that self.lastinsert was updated
# because of the failure of the preceding lookup.
#
	def instest(self, k, v):
		tnode = self.lookup(k)
		if tnode == None:
			self.insert(k, v)
			tnode = self.lastinsert
		return tnode
#
# Deletion, still following the lead of Julienne Walker although, you know,
# rewriting pretty freely. Again the public method is part of a tree and 
# handles the special case of the empty tree. __delete() does the recursion.
#
	def delete(self, k):
		if self.root != NIL_NODE: # we are not an empty tree
			self.root = self.__delete(self.root, k)
#
# Recursive deletion with nonrecursive skew and split. This is the second
# version Walker gives, described as "simple, but unconventional enough
# to be confusing." Yup. See her discussion for why it is always enough
# to do three skews and two splits. Also recall that the skew and split
# routines are conditional and do nothing but a test when not needed.
#
	def __delete(self, tnode, k):
		if tnode != NIL_NODE:
			if k == tnode.key:
				if (tnode.subs[0] != NIL_NODE) & (tnode.subs[1] != NIL_NODE) :
					heir = tnode.subs[0]
					while heir.subs[1] != NIL_NODE:
						heir = heir.subs[1]
					tnode.key = heir.key
					tnode.value = heir.value
					tnode.subs[0] = self.__delete(tnode.subs[0], tnode.key)
				else:
					tnode = tnode.subs[tnode.subs[0]==NIL_NODE]
			else:
				side = tnode.key < k # side==0 on key > OR EQUAL
				tnode.subs[side] = self.__delete(tnode.subs[side], k)
		lv = tnode.level-1
		if (tnode.subs[0].level < lv) | (tnode.subs[1].level < lv) :
			tnode.level = lv
			if tnode.subs[1].level > lv:
				tnode.subs[1].level = lv
			tnode = self.__skew(tnode)
			tnode.subs[1] = self.__skew(tnode.subs[1])
			tnode.subs[1].subs[1] = self.__skew(tnode.subs[1].subs[1])
			tnode = self.__split(tnode)
			tnode.subs[1] = self.__split(tnode.subs[1])
		return tnode


