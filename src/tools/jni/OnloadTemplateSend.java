/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
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

/** JNI wrapper for the Onload Template Send interface.
 * Also used as a wrapper for a handle to a Template.
 * NOTE:
 *   This class offers both the static templated send methods, and also wraps
 *   the template opaque handle.
 *   You do need to be careful not to throw away the reference until sent or
 *   aborted, and especially not to keep ownership after that.
 */
public class OnloadTemplateSend {

  /* Pass as flag to UpdateTemplate to actually perform the send. */
  public static final int ONLOAD_TEMPLATE_FLAGS_SEND_NOW = 0x1;
  /* Pass as flag to UpdateTemplate to make the send nonblocking. */
  public static final int ONLOAD_TEMPLATE_FLAGS_DONTWAIT = 0x40;

  /** @return true if JNI supports templated send. */
  public native static boolean IsTemplatedSendEnabled ();

  /** Allocate a template
   * @param fd		The socket to allocate the template for.
   * @param o_handle	Hold the handle in this object.
   * @param data	Initial packet data.
   * @param flags	Must be 0 currently.
   * @return 0, or a negative error code.
   */
  public native static int Alloc ( int fd, OnloadTemplateSend o_handle,
                                   java.nio.ByteBuffer data,
                                   int flags);
  /** Allocate a template
   * @param socket	The socket to allocate the template for.
   * @param o_handle	Hold the handle in this object.
   * @param data	Initial packet data.
   * @param flags	Must be 0 currently.
   * @return 0, or a negative error code.
   */
  public native static int Alloc ( java.net.ServerSocket socket,
                                   OnloadTemplateSend o_handle,
                                   java.nio.ByteBuffer data,
                                   int flags);
  /** Allocate a template
   * @param socket	The socket to allocate the template for.
   * @param o_handle	Hold the handle in this object.
   * @param data	Initial packet data.
   * @param flags	Must be 0 currently.
   * @return 0, or a negative error code.
   */
  public native static int Alloc ( java.net.Socket socket,
                                   OnloadTemplateSend o_handle,
                                   java.nio.ByteBuffer data,
                                   int flags);
  /** Allocate a template
   * @param socket	The socket to allocate the template for.
   * @param o_handle	Hold the handle in this object.
   * @param data	Initial packet data.
   * @param flags	Must be 0 currently.
   * @return 0, or a negative error code.
   */
  public native static int Alloc ( java.io.FileDescriptor socket,
                                   OnloadTemplateSend o_handle,
                                   java.nio.ByteBuffer data,
                                   int flags);


  /* NOTE: These is no variant that uses Datagram Sockets;
   * templated send is TCP only right now.
   */

  /** Update, and optionally send, a template.
   * @param io_handle	The template.
   * @param data	The data to use.
   * @param offset	Where in the packet to put the data.
   * @param flags	ONLOAD_TEMPLATE_FLAGS_SEND_NOW to send.
   * @return 0, or a negative error code.
   */
  public native static int Update ( OnloadTemplateSend io_handle,
                                    java.nio.ByteBuffer data,
                                    int offset, int flags );

  /** Cancel a template.
   * @param fd		The socket this template is for.
   * @param io_handle	The template.
   * @return 0, or a negative error code.
   */
  public native static int Abort ( OnloadTemplateSend io_handle );

  /** Set in the Alloc() Update() and Abort() methods.
   * Should not be set directly. */
  private long opaque;
  /** The file descriptor.  Set by Alloc. */
  private int fd;

  /** Default constructor. */
  public OnloadTemplateSend() {
	opaque = -1;
	fd = -1;
  }

  public static void main(String[] args) throws java.net.SocketException,
                                                java.io.IOException
  {
    if ( OnloadTemplateSend.IsTemplatedSendEnabled() ) {
      int rc;
      boolean ok = true;

      System.out.println( "Onload present." );
      System.out.println( "Testing.\n\n" );

      OnloadTemplateSend t = new OnloadTemplateSend();
      java.nio.ByteBuffer data = java.nio.ByteBuffer.allocateDirect( 50 );

      System.out.println( "\nExpected: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [x]" );
      java.net.ServerSocket s = new java.net.ServerSocket( 5312 );

      rc = OnloadTemplateSend.Alloc( s, t, data, 0 );
      if ( rc == -107 ) {
        System.out.println( "OK : Template allocation function returns -ENOTCONN as expected." );
      } else if ( rc == -94 ) {
        System.out.println( "OK : Template allocation function returns -ESOCKTNOSUPPORT as expected." );
      } else {
        System.out.println( "BAD: Template allocation function returns " + rc );
        ok = false;
      }
      /* TODO: Ideally, actually connect a socket and test, but that needs two hosts */

      if ( ok ) {
        System.out.println( "\n\t\tTest Passed" );
      } else {
        System.out.println( "\n\t\tTest FAILED" );
      }
    } else {
      System.out.println( "Template Send not enabled." );
    }
  }

  /** OnloadTemplateSend relies upon the OnloadExt C library */
  static{
    System.loadLibrary("OnloadExt");
  }
}
