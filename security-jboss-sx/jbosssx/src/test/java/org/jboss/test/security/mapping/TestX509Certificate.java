/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
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
package org.jboss.test.security.mapping;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

//$Id$

/**
 *  Test X509Certificate
 *  @author Anil.Saldhana@redhat.com
 *  @since  Oct 5, 2007 
 *  @version $Revision$
 */
public class TestX509Certificate extends X509Certificate
{
   X500Principal issuer = null;
   X500Principal subject = null;
   
   public TestX509Certificate(X500Principal issuer, X500Principal subject)
   {
     this.issuer = issuer;   
     this.subject = subject;
   }

   @Override
   public void checkValidity() 
   throws CertificateExpiredException, CertificateNotYetValidException
   { 
   }

   @Override
   public void checkValidity(Date date) 
   throws CertificateExpiredException, CertificateNotYetValidException
   {   
   }

   @Override
   public int getBasicConstraints()
   {
      return 0;
   }

   @Override
   public Principal getIssuerDN()
   {
     return issuer;
   }

   @Override
   public boolean[] getIssuerUniqueID()
   {
     return null;
   }

   @Override
   public boolean[] getKeyUsage()
   {
     return null;
   }

   @Override
   public Date getNotAfter()
   {
     return null;
   }

   @Override
   public Date getNotBefore()
   {
     return null;
   }

   @Override
   public BigInteger getSerialNumber()
   {
     return null;
   }

   @Override
   public String getSigAlgName()
   {
     return null;
   }

   @Override
   public String getSigAlgOID()
   {
     return null;
   }

   @Override
   public byte[] getSigAlgParams()
   {
     return null;
   }

   @Override
   public byte[] getSignature()
   {
     return null;
   }

   @Override
   public Principal getSubjectDN()
   {
     return subject;
   }

   @Override
   public boolean[] getSubjectUniqueID()
   {
     return null;
   }

   @Override
   public byte[] getTBSCertificate() throws CertificateEncodingException
   {
     return null;
   }

   @Override
   public int getVersion()
   {
     return 0;
   }

   @Override
   public byte[] getEncoded() throws CertificateEncodingException
   {
     return null;
   }

   @Override
   public PublicKey getPublicKey()
   {
     return null;
   }

   @Override
   public String toString()
   {
     return null;
   }

   @Override
   public void verify(PublicKey arg0) 
   throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
         NoSuchProviderException, SignatureException
   {
   }

   @Override
   public void verify(PublicKey arg0, String arg1) 
   throws CertificateException, NoSuchAlgorithmException,
         InvalidKeyException, NoSuchProviderException, SignatureException
   {   
   }

   public Set<String> getCriticalExtensionOIDs()
   {
     return null;
   }

   public byte[] getExtensionValue(String arg0)
   {
     return null;
   }

   public Set<String> getNonCriticalExtensionOIDs()
   {
     return null;
   }

   public boolean hasUnsupportedCriticalExtension()
   {
     return false;
   }
}