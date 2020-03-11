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

/** JNI wrapper for the Onload Zerocopy interface.
 * Also used as a wrapper for a zerocopy packet buffer.
 * NOTE:
 *   This class offers both the static zerocopy methods, and also wraps the
 *   zerocopy buffer (which has a data buffer, and some opaque handles)
 *   You do need to be careful not to throw away references until zerocopy has
 *   taken ownership - and equally not to keep a reference after zerocopy has
 *   taken that ownership.
 */
public class OnloadZeroCopy {
  /** Interface for a Zerocopy receive callback.
   */
  public abstract interface Callback {
    /** Interface for a Zerocopy receive callback.
     *
     * You need to implement this for your callbacks.
     * Typically, ownership will revert to zerocopy when this function returns.
     * Return ONLOAD_ZC_KEEP if you want to keep ownership of this buffer.
     */
    public abstract int RecvCallback( OnloadZeroCopy[] data, int flags );
  };
  
  /** The packet buffer */
  public java.nio.ByteBuffer  buffer;
  /** Set in the Alloc() and Recv() methods, should not be set directly. */
  private long     opaque;
  /** @see GetFd()  Set before your callback is invoked. */
  private int      associated_fd;
  
  /** Default constructor. */
  public OnloadZeroCopy() {
    opaque = 0;
    associated_fd = -1;
  }
  
  /** Find the file descriptor that this buffer is associated with.
   * It will be valid when your callback is invoked.
   * @return The native file descriptor.
   * @see Alloc()
   */
  public int GetFd()       { return associated_fd; }
  
  /** Returns internal zerocopy state.
   * You're not expected to need to use this.
   * @return Native state data.
   */
  public long GetOpaque()  { return opaque; }
  
  /** Flag that can be set when calling into Recv()
   * Requests that kernel packets may also be received this way.
   * @see Recv() */
  public static final int ONLOAD_MSG_RECV_OS_INLINE  = 0x1;
  /** Flag that can be set when calling into Recv()
   * Requests that the Recv() call not block if no data available. 
   * @see Recv() */
  public static final int ONLOAD_MSG_DONTWAIT    = 0x40;
  
  /** Flag that can be sent to your callback
   * Indicates that you are not the sole consume of this data, and you should
   * not modify this buffer.
   * @see RecvCallback() */
  public static final int ONLOAD_ZC_MSG_SHARED    = 0x1;
  /** Flags that can be sent to your callback
   * A hint that no more data will be available for a while.
   * @see RecvCallback() */
  public static final int ONLOAD_ZC_END_OF_BURST    = 0x2;
  
  /** Flag your callback can return, to indicate that you are willing to
   * to process more data.
   * @see RecvCallback() */
  public static final int ONLOAD_ZC_CONTINUE    = 0x0;
  /** Flag your callback can return, to indicate that you want to stop
   * processing data for now, and return out of the Recv().
   * @see RecvCallback() */
  public static final int ONLOAD_ZC_TERMINATE    = 0x1;
  /** Flag your callback can return, to indicate that you want to keep
   * ownership of the buffer.  (Be sure to call Release() on it later.)
   * @see RecvCallback() */
  public static final int ONLOAD_ZC_KEEP      = 0x2;
  /** Flag your callback can return, not currently useful. */
  public static final int ONLOAD_ZC_MODIFIED    = 0x4;
  
  /** Allocate with no space for a header.  @see Alloc() */
  public static final int ONLOAD_ZC_BUFFER_HDR_NONE  = 0x0;
  /** Allocate with space for a UDP header.  @see Alloc() */
  public static final int ONLOAD_ZC_BUFFER_HDR_UDP  = 0x1;
  /** Allocate with no space for a TCP header.  @see Alloc() */
  public static final int ONLOAD_ZC_BUFFER_HDR_TCP  = 0x2;
  
  /** Do not actually send the packet(s) yet, wait for more. @see Send() */
  public static final int ONLOAD_MSG_NOSIGNAL    = 0x4000;
  /** Hint that more data will be sent soon. @see Send() */
  public static final int ONLOAD_MSG_MORE        = 0x8000;
  
  /** Check whether ZeroCopy is available.
   * Not all JRE can support it. Onload also has to be in use.
   * @return True if both onload and DirectByteBuffer are available.
   */
  public native static boolean IsZeroCopyEnabled();
  
  /** Allocate buffers for sending - you now own them.
   * @param flags   expects one of ONLOAD_ZC_BUFFER_HDR_*
   * @param o_array An array to fill with the new buffers.
   * @param fd      The socket that will own these buffers.
   * @return the number of buffers allocated, or negative in case of an error.
   * @see ONLOAD_ZC_BUFFER_HDR_NONE
   * @see ONLOAD_ZC_BUFFER_HDR_UDP
   * @see ONLOAD_ZC_BUFFER_HDR_TCP
   */
  public native static int Alloc( int flags, OnloadZeroCopy[] o_array, int fd );
  /** Allocate buffers for sending - you now own them.
   * This relies on internal details of the socket class
   * and probably only works with specific class libraries.
   * Use the fd version when possible - it's faster anyway.
   * @param flags   expects one of ONLOAD_ZC_BUFFER_HDR_*
   * @param o_array An array to fill with the new buffers.
   * @param socker  The socket that will own these buffers.
   * @return the number of buffers allocated, or negative in case of an error.
   * @see ONLOAD_ZC_BUFFER_HDR_NONE
   * @see ONLOAD_ZC_BUFFER_HDR_UDP
   * @see ONLOAD_ZC_BUFFER_HDR_TCP
   */
  public native static int Alloc( int flags, OnloadZeroCopy[] o_array,
                                  java.io.FileDescriptor socket );
  /** Allocate buffers for sending - you now own them.
   * This relies on internal details of the socket class
   * and probably only works with specific class libraries.
   * Use the fd version when possible - it's faster anyway.
   * @param flags   expects one of ONLOAD_ZC_BUFFER_HDR_*
   * @param o_array An array to fill with the new buffers.
   * @param socker  The socket that will own these buffers.
   * @return the number of buffers allocated, or negative in case of an error.
   * @see ONLOAD_ZC_BUFFER_HDR_NONE
   * @see ONLOAD_ZC_BUFFER_HDR_UDP
   * @see ONLOAD_ZC_BUFFER_HDR_TCP
   */
  public native static int Alloc( int flags, OnloadZeroCopy[] o_array,
                                  java.net.DatagramSocket socket );
  /** Allocate buffers for sending - you now own them.
   * This relies on internal details of the socket class
   * and probably only works with specific class libraries.
   * Use the fd version when possible - it's faster anyway.
   * @param flags   expects one of ONLOAD_ZC_BUFFER_HDR_*
   * @param o_array An array to fill with the new buffers.
   * @param socker  The socket that will own these buffers.
   * @return the number of buffers allocated, or negative in case of an error.
   * @see ONLOAD_ZC_BUFFER_HDR_NONE
   * @see ONLOAD_ZC_BUFFER_HDR_UDP
   * @see ONLOAD_ZC_BUFFER_HDR_TCP
   */
  public native static int Alloc( int flags, OnloadZeroCopy[] o_array,
                                  java.net.ServerSocket socket );
  /** Allocate buffers for sending - you now own them.
   * This relies on internal details of the socket class
   * and probably only works with specific class libraries.
   * Use the fd version when possible - it's faster anyway.
   * @param flags   expects one of ONLOAD_ZC_BUFFER_HDR_*
   * @param o_array An array to fill with the new buffers.
   * @param socker  The socket that will own these buffers.
   * @return the number of buffers allocated, or negative in case of an error.
   * @see ONLOAD_ZC_BUFFER_HDR_NONE
   * @see ONLOAD_ZC_BUFFER_HDR_UDP
   * @see ONLOAD_ZC_BUFFER_HDR_TCP
   */
  public native static int Alloc( int flags, OnloadZeroCopy[] o_array,
                                  java.net.Socket socket );
  
  /** Release a buffer.
   * Don't hold a reference after you pass into this function!
   * Don't pass into this function unless you are have ownership!
   * @param buffer The buffer to release
   * @return 0 on success, or a negative error code.
   */
  public native static int Release( OnloadZeroCopy buffer );
  /** Release multiple buffers.
   * Don't hold a reference after you pass into this function!
   * Don't pass into this function unless you are have ownership!
   * @param buffers The array of buffers to release
   * @return the number of buffers released, or a negative error code.
   */
  public native static int Release( OnloadZeroCopy[] buffers );
  
  /** Receive data in the given socket.  Your callback function will be called
   * for any packets that are ready for processing.
   * NOTE: ZeroCopy receive is only supported for UDP
   * @param cb    your callback handler.
   * @param flags do you want to wait, do you want to receive kernel packets?
   * @param fd    the socket to receive on.
   * @return 0 for success, or -ve for failure.
   * @see ONLOAD_MSG_RECV_OS_INLINE
   * @see ONLOAD_MSG_DONTWAIT
   */
  public native static int Recv( Callback cb, int flags, int fd );
  /** Receive data in the given socket.  Your callback function will be called
   * for any packets that are ready for processing.
   * NOTE: ZeroCopy receive is only supported for UDP
   * Java works quite hard to NOT expose the file descriptor.  This relies on
   * internal details of the socket class and probably only works with specific
   * class libraries.  Use the fd version when possible - it's faster anyway.
   * @param cb     your callback handler.
   * @param flags  do you want to wait, do you want to receive kernel packets?
   * @param socket the socket to receive on.
   * @return 0 for success, or -ve for failure.
   * @see ONLOAD_MSG_RECV_OS_INLINE
   * @see ONLOAD_MSG_DONTWAIT
   */
  public native static int Recv( Callback cb, int flags,
                                 java.io.FileDescriptor socket );
  /** Receive data in the given socket.  Your callback function will be called
   * for any packets that are ready for processing.
   * NOTE: ZeroCopy receive is only supported for UDP
   * Java works quite hard to NOT expose the file descriptor.  This relies on
   * internal details of the socket class and probably only works with specific
   * class libraries.  Use the fd version when possible - it's faster anyway.
   * @param cb     your callback handler.
   * @param flags  do you want to wait, do you want to receive kernel packets?
   * @param socket the socket to receive on.
   * @return 0 for success, or -ve for failure.
   * @see ONLOAD_MSG_RECV_OS_INLINE
   * @see ONLOAD_MSG_DONTWAIT
   */
  public native static int Recv( Callback cb, int flags,
                                 java.net.DatagramSocket socket );
  /** Receive data in the given socket.  Your callback function will be called
   * for any packets that are ready for processing.
   * NOTE: ZeroCopy receive is only supported for UDP
   * Java works quite hard to NOT expose the file descriptor.  This relies on
   * internal details of the socket class and probably only works with specific
   * class libraries.  Use the fd version when possible - it's faster anyway.
   * @param cb     your callback handler.
   * @param flags  do you want to wait, do you want to receive kernel packets?
   * @param socket the socket to receive on.
   * @return 0 for success, or -ve for failure.
   * @see ONLOAD_MSG_RECV_OS_INLINE
   * @see ONLOAD_MSG_DONTWAIT
   */
  public native static int Recv( Callback cb, int flags,
                                 java.net.ServerSocket socket );
  /** Receive data in the given socket.  Your callback function will be called
   * for any packets that are ready for processing.
   * NOTE: ZeroCopy receive is only supported for UDP
   * Java works quite hard to NOT expose the file descriptor.  This relies on
   * internal details of the socket class and probably only works with specific
   * class libraries.  Use the fd version when possible - it's faster anyway.
   * @param cb     your callback handler.
   * @param flags  do you want to wait, do you want to receive kernel packets?
   * @param socket the socket to receive on.
   * @return 0 for success, or -ve for failure.
   * @see ONLOAD_MSG_RECV_OS_INLINE
   * @see ONLOAD_MSG_DONTWAIT
   */
  public native static int Recv( Callback cb, int flags,
                                 java.net.Socket socket );
  /** Send one or more packets.
   * Zerocopy only supports TCP send at this time, and so the socket must
   * already be connected.
   * Note that this function takes ownership of the provided buffers.  You must
   * not release them, or modify them, after calling this function.
   * @param msgs  the data to send.
   * @param flags whether to send immediately, or to hold off for more.
   * @param fd    the socket to send on.
   * @return 0 if succesful, or a negative error code if not.
   */
  public native static int Send( OnloadZeroCopy[] msgs, int flags, int fd );
  /** Send one or more packets.
   * Zerocopy only supports TCP send at this time, and so the socket must
   * already be connected.
   * Note that this function takes ownership of the provided buffers.  You must
   * not release them, or modify them, after calling this function.
   * Java works quite hard to NOT expose the file descriptor.  This method
   * relies on internal details and probably only works with specific class
   * libraries.  Use the fd version when possible - it's faster anyway.
   * @param msgs  the data to send.
   * @param flags whether to send immediately, or to hold off for more.
   * @param fd    the socket to send on.
   * @return 0 if succesful, or a negative error code if not.
   */
  public native static int Send( OnloadZeroCopy[] msgs, int flags,
                                 java.io.FileDescriptor socket );
  /** Send one or more packets.
   * Zerocopy only supports TCP send at this time, and so the socket must
   * already be connected.
   * Note that this function takes ownership of the provided buffers.  You must
   * not release them, or modify them, after calling this function.
   * Java works quite hard to NOT expose the file descriptor.  This method
   * relies on internal details and probably only works with specific class
   * libraries.  Use the fd version when possible - it's faster anyway.
   * @param msgs  the data to send.
   * @param flags whether to send immediately, or to hold off for more.
   * @param fd    the socket to send on.
   * @return 0 if succesful, or a negative error code if not.
   */
  public native static int Send( OnloadZeroCopy[] msgs, int flags,
                                 java.net.ServerSocket socket );
  /** Send one or more packets.
   * Zerocopy only supports TCP send at this time, and so the socket must
   * already be connected.
   * Note that this function takes ownership of the provided buffers.  You must
   * not release them, or modify them, after calling this function.
   * Java works quite hard to NOT expose the file descriptor.  This method
   * relies on internal details and probably only works with specific class
   * libraries.  Use the fd version when possible - it's faster anyway.
   * @param msgs  the data to send.
   * @param flags whether to send immediately, or to hold off for more.
   * @param fd    the socket to send on.
   * @return 0 if succesful, or a negative error code if not.
   */
  public native static int Send( OnloadZeroCopy[] msgs, int flags,
                                 java.net.Socket socket );
  
  /** Simple unit test and example */
  public static void main(String[] args) throws java.net.SocketException,
                                                java.io.IOException
  {
    class CallbackTest implements Callback
    {
      public int RecvCallback( OnloadZeroCopy[] data, int flags )
      {
        System.out.println( "Callback! flags: " + flags
                          + " Data: " + data[0].buffer
                          + ": " + data[0].buffer.get() );
        return ONLOAD_ZC_CONTINUE;
      }
    }
    if ( OnloadZeroCopy.IsZeroCopyEnabled() ) {
      boolean ok = true;
      System.out.println( "Zerocopy enabled." );
      System.out.println( "Testing.\n\n" );
      
      java.net.DatagramSocket s = new java.net.DatagramSocket( 5312 );

      System.out.println( "Expect: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [x]" );

      java.net.ServerSocket s2 = new java.net.ServerSocket( 5313 );
      java.net.Socket s3 = new java.net.Socket( "localhost", 5313 );
      java.net.Socket connectedSocket = s2.accept();
      java.io.OutputStream w = s3.getOutputStream();
      java.io.InputStream r = connectedSocket.getInputStream();
      CallbackTest cb = new CallbackTest();
      OnloadZeroCopy[] array = new OnloadZeroCopy[1];
      
      int got = OnloadZeroCopy.Alloc( OnloadZeroCopy.ONLOAD_ZC_BUFFER_HDR_NONE,
                                      array, s2 );
      System.out.println( "\n        zc_alloc got " + got  );
      System.out.println( "Expect: zc_alloc got 0" );
      ok &= got == 0;
      /*
      // For debugging
      System.out.println( "with " + array[0].buffer );
      System.out.println( "and " + array[0].GetOpaque()
                        + " and fd " + array[0].GetFd() );
      System.out.println( array[0].buffer
                        + " ByteArray? " + array[0].buffer.hasArray() );
      */
      array[0].buffer.put( "TestData".getBytes() );
      w.write( "Test".getBytes() );
      
      int sent = OnloadZeroCopy.Send( array, 0, s3 );
      System.out.println( "\n        zc_send returned " + sent );
      System.out.println( "Expect: zc_send returned 0" );
      System.out.println( "or:     zc_send returned -94" );
      ok &= sent==0 || sent==-94;

      System.out.println( "\n        " + r.available() + " bytes arrived at other end." );
      System.out.println( "Expect: n bytes arrived at other end." );
      ok &= r.available() > 0;
      
      int rd = OnloadZeroCopy.Recv( cb, ONLOAD_MSG_DONTWAIT, s );
      System.out.println( "\n        zc_recv returns " + rd );
      System.out.println( "Expect: zc_recv returns 0" );
      System.out.println( "or:     zc_recv returns -11" );
      ok &= rd==0 || rd==-11;
      
      if ( sent >= 0 ) {
        // Sent has taken ownership of that buffer.
        // Allocate a new one so that we can test freeing.
        OnloadZeroCopy.Alloc( OnloadZeroCopy.ONLOAD_ZC_BUFFER_HDR_NONE,
                              array, s2 );
      }
      int released = OnloadZeroCopy.Release(array);
      System.out.println( "\n        release returns " + released );
      System.out.println( "Expect: release returns 1" );
      ok &= released == 1;
      
      s.close();
      s2.close();
      s3.close();
      
      if ( ok )
        System.out.println( "\n\t\tTest Passed" );
      else
        System.out.println( "\n\t\tTest FAILED" );
      
    } else {
      System.out.println( "Zerocopy not enabled." );
    }
  }

  /** OnloadZeroCopy relies upon the OnloadExt C library */
  static{
    System.loadLibrary("OnloadExt");
  }
};
