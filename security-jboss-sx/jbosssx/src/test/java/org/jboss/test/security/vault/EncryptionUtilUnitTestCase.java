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
package org.jboss.test.security.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.picketbox.util.EncryptionUtil;
import org.picketbox.util.KeyStoreUtil;

/**
 * Unit test {@link EncryptionUtil}
 * @author Anil.Saldhana@redhat.com
 * @since Aug 12, 2011
 */
public class EncryptionUtilUnitTestCase
{
   String keyStoreURL = "src/test/resources/keystore/vault.keystore";
   String keyStorePass = "vault22";
   String alias = "vault";
   
   @Test
   public void testEncryptDecrypt() throws Exception
   {
      KeyStore ks = KeyStoreUtil.getKeyStore(keyStoreURL, keyStorePass.toCharArray());
      assertNotNull(ks);
      EncryptionUtil encUtil = new EncryptionUtil("AES", 128);
      
      PublicKey publicKey = KeyStoreUtil.getPublicKey(ks, "vault", keyStorePass.toCharArray());
      assertNotNull(publicKey);
      
      SecretKey secretKey = encUtil.generateKey();
      
      byte[] encryptedData = encUtil.encrypt(keyStorePass.getBytes(), publicKey, secretKey);
      
      KeyPair keypair = KeyStoreUtil.getPrivateKey(ks, alias, keyStorePass.toCharArray());
      byte[] decryptedData = encUtil.decrypt(encryptedData, keypair, secretKey);
      assertEquals(keyStorePass, new String(decryptedData));
   }

}