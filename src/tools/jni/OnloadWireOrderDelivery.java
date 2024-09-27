/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2019 Xilinx, Inc. */
/****************************************************************************
 * Java linkage for onload WODA library.
 *
 * Copyright 2007-2016: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 ****************************************************************************
 */

import java.util.*;

/** JNI wrapper for the Onload WODA API.
 * This function can only be used if EF_UL_EPOLL=1, which is the default, or
 * EF_UL_EPOLL=3.  Hardware timestamping must also be available.
 * It will only return useful results if all sockets are within
 * a single stack.
 * Usage of this class requires you to manage file descriptors.
 */
public class OnloadWireOrderDelivery {
  public static class FdEvent {
    /** Wire order guarantees the next few bytes on a given file descriptor
     * arrived before anything else in the set.
     * Note that an fd may be returned without a timestamp -
     * in such a case, this data does not have any guaranteed ordering
     * with respect to any other item in the set.
     */
    /** The number of bytes that can be read and still maintain ordering */
    int available;
    /** The user data supplied via Ctl */
    Object data;
    /** The time the first available byte arrived at (coarse) */
    long seconds;
    /** The time the first available byte arrived at (fine) */
    long nanoseconds;
    /** The file descriptor the event came from */
    int fd;
  }
  
  /**
   * @class FdSet  This is the epoll set itself.  Add your sockets to it, and query it.
   */
  public static class FdSet {
    /** @param max the maximum number of sockets this set will have to contain. */
    public FdSet(int max)
    {
      int handle;
      this.handle = 0;
      java.util.Map inner = new java.util.HashMap();
      this.map = java.util.Collections.synchronizedMap(inner);
      handle = this.Allocate(max);
      if ( handle > 0 )
        this.handle = handle;
    }
    protected void finalize()
    {
      this.Destroy();
    }
    
    private int handle;  /** Internal data used by native code */
    private java.util.Map map; /** Mapping of fd's to objects */

    
    /** Internal method, used by the constructor */
    private native int Allocate(int max);
    
    /** Called by the finalizer, but you could call it earlier to free up resources if you wish
     *  It is _not_ safe to keep using this object after this has been called.
     */
    public native int Destroy();
    
    /** Analogous to epoll_ctl
     * @param fd the socket to be (added/modified/removed)
     * @param op the operation to occur (EPOLL_CTL_ADD/_MOD/_DEL)
     * @param data Optional user data which will be returned when this socket is ready
     *        NOTE: If using EPOLL_CTL_MOD, this value must be the same as it was with EPOLL_CTL_ADD.
     *              If you need to change it, use _DEL then _ADD the new one.
     *        NOTE: When calling EPOLL_CTL_DEL, this value is ignored.
     * @param events (EPOLLIN / EPOLLPRI etc.)
     * @return 0, or a negative failure code.
     * @note This method does NOT keep a strong reference to your data item; and so should NOT be your only
     *       reference to an object, as it will not prevent it from being garbage collected.
     */
    public int Ctl(int fd, int op, Object data, int events)
    {
      int rval = this._Ctl(fd, op, data, events);
      if ( rval >= 0 ) {
        switch (op) {
        case EPOLL_CTL_ADD:
          this.map.put( fd, data );
          break;
        case EPOLL_CTL_MOD:
          this.map.put( fd, data );
          break;
        case EPOLL_CTL_DEL:
          this.map.remove( fd );
          break;
        }
      }
      return rval;
    }
    private native int _Ctl(int fd, int op, Object data, int events);

    /** Fill out an events array with the next available reads.  Analogous to epoll_wait
     * @param results an array of results objects; could usefully be as large as
     *        the number of items currently in the Woda set.
     * @param timeout in milliseconds (if no sockets have data ready).
     * @return The number of results filled out; or a negative failure code.
     */
    public int Wait(FdEvent[] results, int timeout)
    {
      int rval = this._Wait(results, timeout);
      int i;
      for( i=0; i<rval; i++ ) {
        results[i].data = this.map.get( results[i].fd );
      }
      return rval;
    }
    private native int _Wait(FdEvent[] results, int timeout);
  }
  
  /** Options to pass in to Ctl as operations */
  public static final int EPOLL_CTL_ADD = 1;
  public static final int EPOLL_CTL_DEL = 2;
  public static final int EPOLL_CTL_MOD = 3;
  
  /** Bitfield to pass in to Ctl as events */
  public static final int EPOLLIN = 0x001;
  public static final int EPOLLPRI = 0x002;
  public static final int EPOLLOUT = 0x004;
  public static final int EPOLLRDNORM = 0x040;
  public static final int EPOLLRDBAND = 0x080;
  public static final int EPOLLWRNORM = 0x100;
  public static final int EPOLLWRBAND = 0x200;
  public static final int EPOLLMSG = 0x400;
  public static final int EPOLLERR = 0x008;
  public static final int EPOLLHUP = 0x010;
  public static final int EPOLLRDHUP = 0x2000;
  public static final int EPOLLWAKEUP = (1 << 29);
  /* EPOLLET and ONESHOT flags are NOT supported by Woda */
  
  /** Cast socket to fd - you should ideally subclass Socket() to get access */
  public static native int GetFd(java.net.DatagramSocket socket);
  public static native int GetFd(java.net.ServerSocket socket);
  public static native int GetFd(java.net.Socket socket);
  public static native int GetFd(java.nio.channels.spi.AbstractSelectableChannel channel);
  public static native int GetFd(java.io.FileDescriptor fd);

  public static void main(String[] args) throws java.net.SocketException,
                                                java.io.IOException
  {
    /* Check EF_RX_TIMESTAMPING is set */
    boolean timestamping_enabled = false;
    java.util.Map<String, String> env = System.getenv();
    for (String envName : env.keySet()) {
        if ( envName.equals("EF_RX_TIMESTAMPING") ) {
          int value = Integer.parseInt(env.get(envName));
          if ( value > 0 )              
            timestamping_enabled = true;
          else
            System.out.println(envName + " is '" + env.get(envName) + "' - it needs to be 1 or more" );
          }
    }
    if ( !timestamping_enabled )
      System.out.println( "Please set EF_RX_TIMESTAMPING=1 or higher" );

    if ( timestamping_enabled ) {
      int rc = 0;
      int numResults;
      boolean ok = true;
      byte b[] = new byte[30];
      long sec;
      long nsec;
      
      /* Sample packet item */
      java.net.DatagramPacket packet = new java.net.DatagramPacket(b, b.length);

      /* Somewhere to return the items */
      OnloadWireOrderDelivery.FdEvent[] results = new OnloadWireOrderDelivery.FdEvent[3];

      /* Set up Sockets, add them to a Woda set */
      java.net.DatagramSocket s1 = new java.net.DatagramSocket( 5400 );
      java.net.DatagramSocket s2 = new java.net.DatagramSocket( 5401 );

      int fd1 = OnloadWireOrderDelivery.GetFd(s1);
      int fd2 = OnloadWireOrderDelivery.GetFd(s2);

      OnloadWireOrderDelivery.FdSet woda = new OnloadWireOrderDelivery.FdSet(2);

      rc = woda.Ctl(fd1, EPOLL_CTL_ADD, s1, EPOLLIN);
      if( rc<0 ) System.out.println("Ctl("+woda+", fd1:"+fd1+") failed: "+rc);
      ok &= rc == 0;
      rc = woda.Ctl(fd2, EPOLL_CTL_ADD, s2, EPOLLIN);
      if( rc<0 ) System.out.println("Ctl("+woda+", fd2:"+fd2+") failed: "+rc);
      ok &= rc == 0;

      /* Only proceed if we have the expected sockets etc. */
      if ( ok ) {
        /* Print banner with usage instructions, and wait */
        System.out.println("Ready.\nPlease have DUT2 send (UDP) 10 bytes to port 5400");
        System.out.println("Then 10 bytes to port 5401");
        System.out.println("And finally another 10 bytes to port 5401");
        System.out.println("e.g.\n    udpsend -s10 -n1 $DUT1:5400; udpsend -s10 -n1 $DUT1:5401; udpsend -s10 -n1 $DUT1:5400");
        System.out.println("Then hit Enter, here, to continue.");
        java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        br.readLine();

        /* Clear out the results array */
        results[0] = new OnloadWireOrderDelivery.FdEvent();
        results[1] = new OnloadWireOrderDelivery.FdEvent();
        results[2] = new OnloadWireOrderDelivery.FdEvent();

        /* Wait at most a couple of seconds for packets to arrive - 3 packets will arrive, but expect to see 2 in the set */
        numResults = woda.Wait(results, 2000);
        if( numResults<0 ) System.out.println("Wait("+woda+") returns: "+numResults);
        if ( numResults == 0 ) {
          System.out.println( "No data seen; did you send?  Are the interfaces up?" );
        }
        if( numResults > 2 ) System.out.println("Wait("+woda+") returns too many items: "+numResults);

        /* Check result validity */
        ok &= numResults == 2;
        ok &= results[0].available == 10;
        ok &= results[1].available == 10;
        ok &= results[0].seconds > 0;
        ok &= results[0].seconds > 0;
        ok &= results[1].seconds > results[0].seconds || (results[1].seconds == results[0].seconds && results[1].nanoseconds > results[0].nanoseconds);
        ok &= java.net.DatagramSocket.class.cast(results[0].data) == s1;
        ok &= java.net.DatagramSocket.class.cast(results[1].data) == s2;
        /* Remember the time of the second packet, to compare it to the third */
        sec = results[1].seconds;
        nsec = results[1].nanoseconds;

        /* Clear out those packets (so that we don't see them again) */
        for( int i=0; i<numResults; i++) {
          java.net.DatagramSocket.class.cast(results[i].data).receive(packet);
          ok &= packet.getLength() == results[i].available;
        }

        /* Clear out the results array */
        results[0] = new OnloadWireOrderDelivery.FdEvent();
        results[1] = new OnloadWireOrderDelivery.FdEvent();
        results[2] = new OnloadWireOrderDelivery.FdEvent();
        
        /* Second wait; should pick up the third packet now */
        numResults = woda.Wait(results, 0);
        if( numResults<0 ) System.out.println("Wait("+woda+") returns: "+numResults);
        
        /* Check result validity */
        ok &= numResults == 1;
        ok &= results[0].available == 10;
        ok &= java.net.DatagramSocket.class.cast(results[0].data) == s1;
        ok &= results[0].seconds > sec || (results[0].seconds == sec && results[0].nanoseconds > nsec);

        /* Clear out those packets too (just for completeness) */
        for( int i=0; i<numResults; i++) {
          java.net.DatagramSocket.class.cast(results[i].data).receive(packet);
          ok &= packet.getLength() == results[i].available;
        }

        /* Destruct the set - don't actually need to do this; but we're testing these operations do not fail */
        rc = woda.Ctl(fd1, EPOLL_CTL_DEL, s1, 0);
        ok &= rc == 0;
        rc = woda.Ctl(fd2, EPOLL_CTL_DEL, s2, 0);
        ok &= rc == 0;
        rc = woda.Destroy();
        ok &= rc == 0;
      }
      if ( ok )
        System.out.println( "\n\t\tTest Passed" );
      else
        System.out.println( "\n\t\tTest FAILED" );
    } else {
      System.out.println( "Timestamping enabled Onload not present.  (Test FAILED)" );
    }
  }

  /* OnloadWireOrderDelivery relies upon the OnloadExt C library */
  static{
    System.loadLibrary("OnloadExt");
  }
}
