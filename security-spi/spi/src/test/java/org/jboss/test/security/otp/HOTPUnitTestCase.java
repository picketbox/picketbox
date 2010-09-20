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

import java.util.Calendar;
import java.util.TimeZone;

import org.jboss.security.otp.HOTP;
import org.jboss.security.otp.HOTPUtil;
import org.junit.Test;

/**
 * Unit test the {@code HOTP}
 * @author Anil.Saldhana@redhat.com
 * @since Sep 13, 2010
 */
public class HOTPUnitTestCase
{
   private String userCode = "SomeCode";

   private int codeDigits = 6;
   private boolean addChecksum = false;
   private int truncationOffset = 0; 
   
   byte[] secret = userCode.getBytes();
   
   int SLEEP_TIME = 10;
   
   @Test
   public void testHOTP() throws Exception
   {
      TimeZone utc = TimeZone.getTimeZone( "UTC" );
      Calendar currentDateTime = Calendar.getInstance( utc ); 
    
      String otp1 = this.getOTP(secret, currentDateTime);
      String otp2 = this.getOTP(secret, currentDateTime);
      
      assertEquals( otp1, otp2 ); 
   }
   
   @Test
   public void testSubmittedHOTP() throws Exception
   { 
      TimeZone utc = TimeZone.getTimeZone( "UTC" );
      Calendar currentDateTime = Calendar.getInstance( utc );
      String otp1 = this.getOTP( secret, currentDateTime );
      
      //System.out.println( "OTP Generated at " + currentDateTime);
      
      System.out.println( "We are going to sleep for " + SLEEP_TIME + " secs" );
      Thread.sleep( SLEEP_TIME * 1000 ); //10 secs
      
      assertTrue( HOTPUtil.validate( otp1, secret,  2 ) );
   }
   
   private String getOTP( byte[] secret, Calendar currentDateTime ) throws Exception
   { 
      long timeInMilis = currentDateTime.getTimeInMillis();
      long movingFactor = timeInMilis;

      return HOTP.generateOTP( secret, movingFactor, codeDigits, addChecksum, truncationOffset );
   }
}