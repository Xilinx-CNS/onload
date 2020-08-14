#! /usr/bin/env python2
#
# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2020 Xilinx, Inc.
#

# This tool is intended to anonymise the output of onload_stackdump
# so that they can be shared without giving away IP addresses

import random
import sys
import re

def ToStrings(xs):
  """ It seems that you can only join() strings, so convert """
  return [ str(x) for x in xs ]

class AnonymiseIp:
  """ Very minimal symmetric encrypt of IP addresses """
  def __init__(self, a=None, b=None, c=None, d=None):
    """ a,b,c,d is the key; randomly selected if not specified """
    if a is None:
      a = random.randint(0,255)
    if b is None:
      b = random.randint(0,255)
    if c is None:
      c = random.randint(0,255)
    if d is None:
      # Don't allow 0.0.0.0 as a key!  Force at least one bit-flip
      d = random.randint(1,255)

    self.ip = "\d+\.\d+\.\d+\.\d+"
    self.A = a
    self.B = b
    self.C = c
    self.D = d

  def Keys(self):
    """ Read back the keys """
    return self.A, self.B, self.C, self.D

  def AnonymiseQuad(self, a, b, c, d):
    """ Encrypt four integers
        Don't anonymise 0.0.0.0 because it is common and obivous to reverse the key. """
    if ( not a and not b and not c and not d ):
      return (0,0,0,0)
    return (a^self.A, b^self.B, c^self.C, d^self.D)

  def AnonymiseIp(self, ip):
    """ Expects an "a.b.c.d" style string or a MatchObject """
    try:
      ip = ip.group(0)
    except AttributeError as e:
      pass

    (a,b,c,d) = ip.split(".")
    quad = self.AnonymiseQuad(int(a),int(b),int(c),int(d))
    return ".".join(ToStrings(quad))

  def ReplaceIps(self, line):
    """ Expects a string which may contain one or more a.b.c.d IPs
        Replaces them with their encrypted equivalents. """
    return re.sub(self.ip, self.AnonymiseIp, line)

  def SelfTest(self):
    """ Check basic functionality """
    base = "224.1.2.3"
    zero = "0.0.0.0"
    assert( self.AnonymiseIp(base) != base )
    assert( self.AnonymiseIp(base) == self.AnonymiseIp(base) )
    assert( self.AnonymiseIp(zero) == zero )
    def reversible(line):
      crypt = self.ReplaceIps(line)
      return ( crypt != line ) and ( self.ReplaceIps(crypt) == line )
    assert( reversible( "UDP 2:81 lcl=  rmt=1.2.3.4:0 UDP" ) )
    assert( reversible( "TCP 2:110 lcl=10.136.18.138:32791 rmt=196.1.2.125:8011 ESTABLISHED" ) )
    assert( reversible( "snd: TO 201.197.200.17:27001 => 0.0.0.0:8012" ) )

def usage():
  print( "Usage: %s <filename> [k e y s]"%sys.argv[0] )
  print( "\tSpecial filename of -- to mean stdin (^D^D to exit)" )
  print( "" )
  print( "This tool is intended to anonymise the output of onload_stackdump" )
  print( "If the key is provided, it can also reverse this." )
  print( "" )
  print( "Specifically - IP addresses will be scrambled, but repeatably" )
  print( "so that we can still tell if multiple sockets were communicating" )
  print( "with the same host, or group - but not what the host or group was" )
  print( "(unless you provide us with the key)" )
  sys.exit(0)


if __name__ == "__main__":
  """ If invoked with no arguments, print out the usage string
      Otherwise, the first argument is the file to work on
      and, optionally, the next four are the key to use. """

  if( len(sys.argv) < 2 ):
    usage()

  if ( len(sys.argv) == 6 ):
    anon = AnonymiseIp( int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]) )
  else:
    anon = AnonymiseIp()

  anon.SelfTest()

  if "--" == sys.argv[1]:
    file = sys.stdin
  else:
    file = open(sys.argv[1],'r')
  for line in file:
    sys.stdout.write( anon.ReplaceIps(line) )

  sys.stderr.write( "Secret key was: %s\n"%" ".join(ToStrings(anon.Keys())) )
