/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.test.security.otp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Locale;

import org.jboss.security.otp.TimeBasedOTP;
import org.jboss.security.otp.TimeBasedOTPUtil;
import org.junit.Test;

/**
 * Unit test the {@code TimeBasedOTP} utility
 * @author Anil.Saldhana@redhat.com
 * @since Sep 20, 2010
 */
public class TimeBasedOTPUnitTestCase
{ 
   /**
    | Time (sec) |    UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
   +------------+---------------+------------------+----------+--------+
   |     59     |   1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
   |            |    00:00:59   |                  |          |        |
   |     59     |   1970-01-01  | 0000000000000001 | 32247374 | SHA256 |
   |            |    00:00:59   |                  |          |        |
   |     59     |   1970-01-01  | 0000000000000001 | 69342147 | SHA512 |
   |            |    00:00:59   |                  |          |        |
   | 1111111109 |   2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
   |            |    01:58:29   |                  |          |        |
   | 1111111109 |   2005-03-18  | 00000000023523EC | 34756375 | SHA256 |
   |            |    01:58:29   |                  |          |        |
   | 1111111109 |   2005-03-18  | 00000000023523EC | 63049338 | SHA512 |
   |            |    01:58:29   |                  |          |        |
   | 1111111111 |   2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
   |            |    01:58:31   |                  |          |        |
   | 1111111111 |   2005-03-18  | 00000000023523ED | 74584430 | SHA256 |
   |            |    01:58:31   |                  |          |        |
   | 1111111111 |   2005-03-18  | 00000000023523ED | 54380122 | SHA512 |
   |            |    01:58:31   |                  |          |        |
   | 1234567890 |   2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
   |            |    23:31:30   |                  |          |        |
   | 1234567890 |   2009-02-13  | 000000000273EF07 | 42829826 | SHA256 |
   |            |    23:31:30   |                  |          |        |
   | 1234567890 |   2009-02-13  | 000000000273EF07 | 76671578 | SHA512 |
   |            |    23:31:30   |                  |          |        |
   | 2000000000 |   2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
   |            |    03:33:20   |                  |          |        |
   | 2000000000 |   2033-05-18  | 0000000003F940AA | 78428693 | SHA256 |
   |            |    03:33:20   |                  |          |        |
   | 2000000000 |   2033-05-18  | 0000000003F940AA | 56464532 | SHA512 |
   |            |    03:33:20   |                  |          |        |
   +------------+---------------+------------------+----------+--------+

    */
 
   String seed = "3132333435363738393031323334353637383930";
   long T0 = 0;
   long X = 30;
   long testTime[] = { 59, 1111111109, 1111111111, 1234567890, 2000000000 };
   
   String steps = "0";
   
   String[] totp = new String[] { "94287082", "32247374", "69342147",
                                  "07081804", "34756375", "63049338",
                                  "14050471", "74584430", "54380122",
                                  "89005924", "42829826", "76671578",
                                  "69279037", "78428693", "56464532" };
   
   int NUMBER_OF_DIGITS = 8;
   
   int SLEEP_TIME = 2;
   
   
   @Test
   public void testTOTP() throws Exception
   {
      int totpIndex = -1;
      
      for(int i=0; i< testTime.length; i++) 
      {
         long T = ( testTime[i] - T0 ) / X;
         steps = Long.toHexString( T ).toUpperCase(Locale.ENGLISH);
         
         // Just get a 16 digit string
         while(steps.length() < 16) 
            steps = "0" + steps;
         
         assertEquals( totp[ ++totpIndex ], TimeBasedOTP.generateTOTP( seed, steps, NUMBER_OF_DIGITS , "HmacSHA1" ) );
         assertEquals( totp[ ++totpIndex ], TimeBasedOTP.generateTOTP( seed, steps, NUMBER_OF_DIGITS , "HmacSHA256" ) );
         assertEquals( totp[ ++totpIndex ], TimeBasedOTP.generateTOTP( seed, steps, NUMBER_OF_DIGITS , "HmacSHA512" ) ); 
     } 
   } 
   
   @Test
   public void testTOTPValidity() throws Exception
   {         
      String totp = TimeBasedOTP.generateTOTP( seed, NUMBER_OF_DIGITS ); 

      System.out.println( "We are going to sleep for " + SLEEP_TIME + " secs" );
      Thread.sleep( SLEEP_TIME * 1000 ); //10 secs
      
      assertTrue( "TOTP validated", TimeBasedOTPUtil.validate( totp, seed.getBytes() , 8 ));
   }
}