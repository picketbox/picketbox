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
package org.jboss.test.authentication.jaas;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import junit.framework.TestCase;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.callback.ObjectCallback;
import org.jboss.security.auth.callback.SecurityAssociationCallback;

/**
 * Unit Test the JBossCallbackHandler
 * @author Anil.Saldhana@redhat.com
 * @since 25 November 2008
 */
public class JBossCallbackHandlerUnitTestCase extends TestCase
{
   public void testCtr() throws Exception
   {
      JBossCallbackHandler cbh = new JBossCallbackHandler(new SimplePrincipal("anil"), "testpass");
      validate(cbh);
   }
   
   public void testSetSecurityInfo() throws Exception
   {
      JBossCallbackHandler cbh = new JBossCallbackHandler();
      cbh.setSecurityInfo(new SimplePrincipal("anil"), "testpass");
      validate(cbh);
   }
   
   public void testSerializability() throws Exception
   {
      JBossCallbackHandler cbh = new JBossCallbackHandler();
      cbh.setSecurityInfo(new SimplePrincipal("anil"), "testpass");
      
      // Serialize to a byte array
      ByteArrayOutputStream bos = new ByteArrayOutputStream() ;
      ObjectOutputStream out = new ObjectOutputStream(bos) ;
      out.writeObject(cbh);
      out.close();
     
      //Deserialize from a byte array
      JBossCallbackHandler otherCBH = null;
      ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
      otherCBH = (JBossCallbackHandler) in.readObject();
      in.close();
      assertNotNull("The deserialized cbh is not null:", otherCBH);
      validate(otherCBH); 
   }
   
   private void validate(JBossCallbackHandler cbh) throws Exception
   {
      SecurityAssociationCallback sacb = new SecurityAssociationCallback();
      NameCallback ncb = new NameCallback("Enter Name");
      ObjectCallback ocb =  new ObjectCallback("Enter pass");
      PasswordCallback passcb = new PasswordCallback("Enter pass", false);
      
      Callback[] callbacks = new Callback[] {sacb, ncb, ocb, passcb};
      
      cbh.handle(callbacks);
      
      assertEquals("anil", sacb.getPrincipal().getName());
      assertEquals("testpass", sacb.getCredential());
      
      assertEquals("anil", ncb.getName());
      assertEquals("testpass", ocb.getCredential());
      assertEquals("testpass", new String(passcb.getPassword()));
   }
}