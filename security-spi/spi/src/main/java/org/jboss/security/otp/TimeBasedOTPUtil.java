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
package org.jboss.security.otp;

import java.security.GeneralSecurityException;

/**
 * Utility class associated with the {@code TimeBasedOTP} class
 * @author Anil.Saldhana@redhat.com
 * @since Sep 20, 2010
 */
public class TimeBasedOTPUtil
{   
   /**
   * Validate a submitted OTP string
   * @param submittedOTP OTP string to validate
   * @param secret Shared secret 
   * @return 
   * @throws GeneralSecurityException
   */
  public static boolean validate( String submittedOTP, byte[] secret, int numDigits ) throws GeneralSecurityException
  {
     String generatedTOTP = TimeBasedOTP.generateTOTP( new String( secret ) , numDigits ); 
     
     System.out.println( "Generated[" + generatedTOTP + "]::Submitted[" + submittedOTP );
     return generatedTOTP.equals( submittedOTP ); 
  } 
}