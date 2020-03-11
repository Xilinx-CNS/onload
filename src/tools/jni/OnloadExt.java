/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Java linkage for onload extention library.
 *
 * Copyright 2007-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 ****************************************************************************
 */

/** JNI wrapper for the Onload extensions API.  Entirely static. */
public class OnloadExt {
    /** File-descriptor information. @see FdStat */
    public static class Stat {
      /** The stack number this fd is owned by. */
      public int stackId;
      /** The name of the stack (if any. */
      public String stackName;
      /** Unique identifier, usually matches the fd. */
      public int endpointId;
      /** Is the socket open, connected, listening etc.
       * @see /src/include/ci/internal/ip.h */
      public int endpointState;
      /** Default constructor */
      public Stat() {
          stackId = 0;
          stackName = "";
          endpointId = 0;
          endpointState = 0;
      }
    };

    /** Apply this name to just this thread.  @see SetStackName() */
    public static final int ONLOAD_THIS_THREAD       = 0;
    /** Apply this name to the whole process.  @see SetStackName() */
    public static final int ONLOAD_ALL_THREADS       = 1;

    /** Undo previous stackname change.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_NOCHANGE    = 0;
    /** Make name local to each thread.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_THREAD      = 1;
    /** Make name local to each process.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_PROCESS     = 2;
    /** Make name local to each user.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_USER        = 3;
    /** Make name global.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_GLOBAL      = 4;
    /** Special stack name value to allow creating unaccelerated sockets.
     * @see SetStackName() */
    public static final String ONLOAD_DONT_ACCELERATE = null;
    
    /** Set all types of spin.  @see SetSpin */
    public static final int ONLOAD_SPIN_ALL          = 0;
    /** Alter spin for UDP receive only.  @see SetSpin */
    public static final int ONLOAD_SPIN_UDP_RECV     = 1;
    /** Alter spin for UDP send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_UDP_SEND     = 2;
    /** Alter spin for TCP receive only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_RECV     = 3;
    /** Alter spin for TCP send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_SEND     = 4;
    /** Alter spin for TCP accept only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_ACCEPT   = 5;
    /** Alter spin for pipe recevie only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PIPE_RECV    = 6;
    /** Alter spin for pipe send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PIPE_SEND    = 7;
    /** Alter spin for select calls only.  @see SetSpin */
    public static final int ONLOAD_SPIN_SELECT       = 8;
    /** Alter spin for poll calls only.  @see SetSpin */
    public static final int ONLOAD_SPIN_POLL         = 9;
    /** Alter spin for TCP connect only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PKT_WAIT     = 10;
    /** Alter spin for epoll only.  @see SetSpin */
    public static final int ONLOAD_SPIN_EPOLL_WAIT   = 11;
    /** Alter spin for when stack is already locked only.  @see SetSpin */
    public static final int ONLOAD_SPIN_STACK_LOCK   = 12;
    /** Alter spin for when socket is already locked only.  @see SetSpin */
    public static final int ONLOAD_SPIN_SOCK_LOCK    = 13;
    /** Alter spin for busy poll.  @see SetSpin */
    public static final int ONLOAD_SPIN_SO_BUSY_POLL = 14;
    /** Alter spin for TCP connect.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_CONNECT  = 15;
    /** Set all spin types set via EF_POLL_USEC. @see SetSpin */
    public static final int ONLOAD_SPIN_MIMIC_EF_POLL= 16;
    /** Is the ONLOAD_MSG_WARM feature supported? @see CheckFeature */
    public static final int ONLOAD_FD_FEAT_MSG_WARM  = 0;
    
    /** Check whether onload extensions are present.
     * @return True if running under onload. */
    public static native boolean IsPresent();
    /** Set the current stack name.
     * From this point onwards, until another call to this function overrides
     * it, sockets created by 'who' will be in 'stackname' (where the name is
     * local to 'scope').  If stackname is ONLOAD_DONT_ACCELERATE, the socket
     * will be unaccelerated and not placed in any stack.
     * @param who       should this call apply to only this thread, or the
     *                  whole process?  (Also used for 
     * @param scope     is the name system wide, or local to this thread etc.
     * @param stackname the stack to use
     * @return 0 on success, or a negative error code.
     * @see ONLOAD_THIS_THREAD
     * @see ONLOAD_ALL_THREADS
     * @see ONLOAD_SCOPE_NOCHANGE
     * @see ONLOAD_SCOPE_THREAD
     * @see ONLOAD_SCOPE_PROCESS
     * @see ONLOAD_SCOPE_USER
     * @see ONLOAD_SCOPE_GLOBAL
     * @see ONLOAD_DONT_ACCELERATE
     */
    public static native int SetStackName (int who, int scope,
                                           String stackname );
    /** Set whether calls from this thread should spin or not.
     * Onload only cares about the underlying system call made, and will obey
     * any timeout specified, so spinning may be limited anyway.
     * @param spin_type the type of call to alter spin settings for.
     * @param spin      True to spin, False to disable spinning.
     * @see ONLOAD_SPIN_ALL
     * @see ONLOAD_SPIN_UDP_RECV
     * @see ONLOAD_SPIN_UDP_SEND
     * @see ONLOAD_SPIN_TCP_RECV
     * @see ONLOAD_SPIN_TCP_SEND
     * @see ONLOAD_SPIN_TCP_ACCEPT
     * @see ONLOAD_SPIN_PIPE_RECV
     * @see ONLOAD_SPIN_PIPE_SEND
     * @see ONLOAD_SPIN_SELECT
     * @see ONLOAD_SPIN_POLL
     * @see ONLOAD_SPIN_PKT_WAIT
     * @see ONLOAD_SPIN_EPOLL_WAIT
     * @see ONLOAD_SPIN_STACK_LOCK
     * @see ONLOAD_SPIN_SOCK_LOCK
     */
    public static native int SetSpin (int spin_type, boolean spin );
    /** Fill out onload statistics for a given socket
     * @param fd   the socket to get information on.
     * @param stat statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (int fd, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.DatagramSocket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.ServerSocket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.Socket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
     public static native int FdStat (java.io.FileDescriptor socket, Stat stat );

    /** Checks whether the given feature is supported.
     * @param fd      The socket to check.
     * @param feature The feature to check support for.
     * @return >0 if supported, <0 if not.
     */
    public static native int CheckFeature ( int fd, int feature );

    /** Remember the name of the current stack.
     * @return 0 or negative error code.
     */
    public static native int SaveStackName ();

    /** Restore the remembered name.
     * @return 0 or negative error code.
     */
    public static native int RestoreStackName ();

    /** Set the specified stack option, for the next stack created.
     * @param option   The option to change.
     * @param value    The new value for it.
     * @return 0 or negative error code.
     */
    public static native int SetStackOption (String option, int value);

    /** Go back to the options specified before SetStackOption was used.
     * @return 0 or negative error code.
     */
    public static native int ResetStackOptions ();

    /** Move a newly created accepted socket to the current stack.
     * @param fd   the socket to get information on.
     * @return 0 or negative error code.
     * @note This method only currently suports connected TCP sockets.
     */
    public static native int MoveFd ( int fd );

    /** Move a newly created accepted socket to the current stack.
     * @param fd   the socket to get information on.
     * @return 0 or negative error code.
     * @note This method only makes sense for connected TCP sockets,
     *       not datagram or server sockets.
     */
    public static native int MoveFd ( java.io.FileDescriptor fd );

    /** Move a newly created accepted socket to the current stack.
     * @param socket   the socket to move.
     * @return 0 or negative error code.
     * @note This method only currently suports connected TCP sockets.
     */
    public static native int MoveFd ( java.net.Socket socket );

    /** Move a newly created accepted socket to the current stack.
     * @param socket   the socket to move.
     * @return 0 or negative error code.
     * @note This method only currently suports connected TCP sockets.
     */
    public static native int MoveFd ( java.net.DatagramSocket socket );

    /** Move a newly created accepted socket to the current stack.
     * @param socket   the socket to move.
     * @return 0 or negative error code.
     * @note This method only currently suports connected TCP sockets.
     */
    public static native int MoveFd ( java.net.ServerSocket socket );

    /** Create a new UDP socket that does not accelerate unicast rx.
     * The newly created socket will not use hardware resources for
     * unicast rx.  Multicast rx will be accelerated and
     * use hardware resources as usual.
     * @param port   port to bind the new socket to.
     * @return new UDP socket or throws exception java.net.SocketException.
     */
    public static java.net.DatagramSocket UnicastNonaccel(int port)
                                            throws java.net.SocketException {
      java.net.DatagramSocket s = new java.net.DatagramSocket(port);
      int rc = UnicastNonaccel_(s);
      if ( rc < 0 )
        throw new java.net.SocketException("Creating UnicastNonaccel socket failed");
      return s;
    }

    private static native int UnicastNonaccel_ ( java.net.DatagramSocket socket );

    /** Simple unit test and example */
    public static void main(String[] args) throws java.net.SocketException,
                                                  java.io.IOException
    {
      Stat stat = new Stat();
      if ( OnloadExt.IsPresent() ) {
        int rc;
        boolean ok = true;

        System.out.println( "Onload present." );
        System.out.println( "Testing.\n\n" );

        java.io.FileDescriptor d = new java.io.FileDescriptor();

        System.out.println( "Expected: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [x]\n" );

        java.net.DatagramSocket ds1 = new java.net.DatagramSocket( 5400 );

        rc = OnloadExt.SetStackName( ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "Mary" );
        ok &= rc==0;

        rc = OnloadExt.SaveStackName();
        ok &= rc==0;

        rc = OnloadExt.SetStackName( ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "Hidden" );
        ok &= rc==0;

        rc = OnloadExt.SetStackName( ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, ONLOAD_DONT_ACCELERATE );
        ok &= rc==0;

        java.net.DatagramSocket ds2 = new java.net.DatagramSocket( 5402 );

        rc = OnloadExt.SetStackOption( "EF_RFC_RTO_MAX", 270 );
        ok &= rc==0;

        System.out.println( "Expected: oo:java[xxx]: onload_stack_opt_set_int: Requested option EF_NOSUCH_OPTION not found" );
        rc = OnloadExt.SetStackOption( "EF_NOSUCH_OPTION", 0 );
        ok &= rc<0;

        rc = OnloadExt.ResetStackOptions();
        ok &= rc==0;

        rc = OnloadExt.RestoreStackName();
        ok &= rc==0;

        if ( !ok ) {
                System.out.println( "Failed before fd_stat." );
        }

        rc = OnloadExt.SetSpin( ONLOAD_SPIN_ALL, true );
        java.net.ServerSocket ss1 = new java.net.ServerSocket( 5401 );
        ok &= rc==0;

        ok &= ( 0 == OnloadExt.CheckFeature( 14, OnloadExt.ONLOAD_FD_FEAT_MSG_WARM ) );

        System.out.println( "Expected: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [y,Mary]" );

        java.net.Socket ss2 = new java.net.Socket( "localhost", 5401 );
        java.net.Socket ss3 = ss1.accept();

        rc = OnloadExt.FdStat( d, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        System.out.println( "Expect: Rval: -22 Stack ID: 0 Name:  Endpoint ID: 0 Endpoint State: 0" );
        ok &= rc <= 0;
        ok &= stat.stackId == 0;
        ok &= stat.stackName.equals("");
        ok &= stat.endpointState == 0;

        rc = OnloadExt.FdStat( ds1, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        System.out.println( "Expect: Rval: x Stack ID: x Name:  Endpoint ID: nn Endpoint State: b000" );
        ok &= rc > 0;
        ok &= stat.stackName.equals("");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 0xb000; //CI_TCP_STATE_UDP

        rc = OnloadExt.FdStat( ds2, stat );
        System.out.println( "\n        Rval: " + rc);
        System.out.println( "Expect: Rval: 0" );
        ok &= rc==0;

        rc = OnloadExt.FdStat( ss1, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        System.out.println( "Expect: Rval: x Stack ID: y Name: Mary Endpoint ID: nn Endpoint State: 1246" );
        ok &= rc > 0;
        ok &= stat.stackName.equals("Mary");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 0x1246; //CI_TCP_LISTEN

        rc = OnloadExt.FdStat( ss2, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        System.out.println( "Expect: Rval: 0 Stack ID: 0 Name:  Endpoint ID: 0 Endpoint State: 0" );
        ok &= rc == 0;
        ok &= stat.stackName.equals("");
        ok &= stat.endpointId == 0;
        ok &= stat.endpointState == 0;

        /* Connected socket */
        System.out.println( "\n** Have DUT2 connect TCP to port 5401 please **" );
        java.net.Socket ss4 = ss1.accept();

        rc = OnloadExt.SetStackName( ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "Joe" );
        ok &= rc==0;
        rc = OnloadExt.MoveFd( ss4 );
        ok &= rc==0;

        rc = OnloadExt.FdStat( ss4, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        System.out.println( "Expect: Rval: x Stack ID: y Name: Joe Endpoint ID: nn Endpoint State: 3331" );
        ok &= rc > 0;
        ok &= stat.stackName.equals("Joe");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 0x3331; //CI_TCP_ESTABLISHED

        java.net.DatagramSocket ds3 = UnicastNonaccel(5403);
        ok &= ds3 != null;

        rc = OnloadExt.FdStat( ds3, stat );
        System.out.println( "\n        Rval: " + rc
                  + " Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + Integer.toHexString(stat.endpointState)
                );
        ok &= rc > 0;
        ok &= stat.stackName.equals("Joe");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 0xb000; //CI_TCP_STATE_UDP
        System.out.println( "Expect: Rval: x Stack ID: y Name: Joe Endpoint ID: nn Endpoint State: b000" );

        ds1.close();
        ds2.close();
        ds3.close();
        ss1.close();
        ss2.close();
        ss3.close();
        ss4.close();

        if ( ok )
          System.out.println( "\n\t\tTest Passed" );
        else
          System.out.println( "\n\t\tTest FAILED" );

      } else {
        System.out.println( "Onload not present." );
      }

    }
    
    /** OnloadExt relies upon the OnloadExt C library */
    static{
      System.loadLibrary("OnloadExt");
    }
}
