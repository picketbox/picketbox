/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.test.security.helpers;

import junit.framework.TestCase;
import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;

import org.jboss.logging.Logger;
import org.jboss.security.ExternalPasswordCache;
import org.jboss.security.Util;
import org.jboss.security.plugins.FilePassword;
import org.jboss.security.util.StringPropertyReplacer;

/**
 org.jboss.security.Util tests
 
 @author Scott.Stark@jboss.org
 @version $Revision: 57211 $
*/
public class SecurityUtilUnitTestCase
   extends TestCase
{
   
   private static Logger log = Logger.getLogger(SecurityUtilUnitTestCase.class);
   private File tmpPassword;
   private File password;

   public SecurityUtilUnitTestCase(String name)
   {
      super(name);
   }

   protected void setUp() throws Exception
   {
      super.setUp();
      // Create a tmp password file for testTmpFilePassword
      tmpPassword = new File(System.getProperty("java.io.tmpdir"), "tmp.password");
      FileWriter writer = new FileWriter(tmpPassword);
      writer.write("password1");
      writer.close();

      // Create the opaque password file for testFilePassword
      password = new File(System.getProperty("java.io.tmpdir")+ "/tst.password");
      String[] args2 = {
         "12345678", // salt
         "17", // count
         "password2", // password
         password.getAbsolutePath() // password-file
      };
      FilePassword.main(args2);
      log.info("Created password file: "+args2[2]);
   }
   protected void tearDown() throws Exception
   {
      tmpPassword.delete();
      password.delete();
      super.tearDown();   
   }

   /**
    * Test {CLASS}org.jboss.security.plugins.TmpFilePassword
    * @throws Exception
    */
   public void testTmpFilePassword() throws Exception
   {
      String passwordCmd = "{CLASS}org.jboss.security.plugins.TmpFilePassword:${java.io.tmpdir}/tmp.password";
      passwordCmd = StringPropertyReplacer.replaceProperties(passwordCmd);
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as external password with comand");
      }
      char[] password = Util.loadPassword(passwordCmd);
      assertTrue("password1", Arrays.equals(password, "password1".toCharArray()));
   }
   /**
    * Test {CLASS}org.jboss.security.plugins.FilePassword
    * @throws Exception
    */
   public void testFilePassword() throws Exception
   {
      String passwordCmd = "{CLASS}org.jboss.security.plugins.FilePassword:${java.io.tmpdir}/tst.password";
      passwordCmd = StringPropertyReplacer.replaceProperties(passwordCmd);
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as class call password");
      }
      char[] password = Util.loadPassword(passwordCmd);
      assertTrue("password2", Arrays.equals(password, "password2".toCharArray()));
   }
   /**
    * Test {EXT}org.jboss.test.security.helpers.ExecPasswordCmd
    * @throws Exception
    */
   public void testExtPassword() throws Exception
   {
      String passwordCmd = buildExtCommand("EXT");
      log.info("Executing password command:" + passwordCmd);
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as external password with comand");
      }
      char[] password = Util.loadPassword(passwordCmd);
      assertTrue("password3", Arrays.equals(password, "password3".toCharArray()));
   }
   
   public void testExtPasswordCache() throws Exception {
      
      // reset ext password the cache
      ExternalPasswordCache.getExternalPasswordCacheInstance().reset();
      
      String passwordCmd = buildExtCommand("EXTC");
      char[] password = Util.loadPassword(passwordCmd + " 4");
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as external password with comand");
      }
      assertTrue("password4", Arrays.equals(password, "password4".toCharArray()));
      char[] cachedPassword = Util.loadPassword(passwordCmd + " 4");
      assertTrue("password4 cached:1", Arrays.equals(password, "password4".toCharArray()));
      assertTrue("password4 cached - real call:1", 
            ExternalPasswordCache.getExternalPasswordCacheInstance().getCachedPasswordsCount() == 1);

      cachedPassword = Util.loadPassword(passwordCmd + " 5");
      assertTrue("password5", Arrays.equals(cachedPassword, "password5".toCharArray()));
      cachedPassword = Util.loadPassword(passwordCmd + " 4");
      assertTrue("password4 cached:2", Arrays.equals(cachedPassword, "password4".toCharArray()));
      assertTrue("password4 cached - real call:2", 
            ExternalPasswordCache.getExternalPasswordCacheInstance().getCachedPasswordsCount() == 2);
      
      cachedPassword = Util.loadPassword(passwordCmd + " 5");
      assertTrue("password5 cached:2", Arrays.equals(cachedPassword, "password5".toCharArray()));
      assertTrue("password5 cached - real call:2", 
            ExternalPasswordCache.getExternalPasswordCacheInstance().getCachedPasswordsCount() == 2);
      
   }
   
   public void testExtPasswordCacheTimeOut() throws Exception {
      
      // reset ext password the cache
      ExternalPasswordCache.getExternalPasswordCacheInstance().reset();
      
      final String TO = "500";
      
      String passwordCmd = buildExtCommand("EXTC:" + TO);
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as external password with comand");
      }
      char[] password4 = Util.loadPassword(passwordCmd + " 4 timeOut");
      assertTrue("password4 timeOut = " + TO, Arrays.equals(new String(password4).substring(0,  9).toCharArray(), "password4".toCharArray()));

      char[] cachedPassword4_2 = Util.loadPassword(passwordCmd + " 4 timeOut");
      assertTrue("password4 timeOut = " + TO + ", cached:1", Arrays.equals(password4, cachedPassword4_2));
      
      long WAIT = 800;
      Thread.sleep(WAIT);
      char[] cachedPassword4_3 = Util.loadPassword(passwordCmd + " 4 timeOut");

      assertFalse("password4 timeOut = " + TO + " cached:1, wait = " + WAIT, 
            Arrays.equals(password4, cachedPassword4_3));

      char[] cachedPassword5 = Util.loadPassword(passwordCmd + " 5 timeOut");
      assertTrue("password5", Arrays.equals(new String(cachedPassword5).substring(0, 9).toCharArray(), "password5".toCharArray()));
      cachedPassword5 = Util.loadPassword(passwordCmd + " 4 timeOut");
      assertTrue("password4 cached - real call:2", 
            ExternalPasswordCache.getExternalPasswordCacheInstance().getCachedPasswordsCount() == 2);
      
      cachedPassword5 = Util.loadPassword(passwordCmd + " 5 timeOut");
      assertTrue("password5 cached - real call:2", 
            ExternalPasswordCache.getExternalPasswordCacheInstance().getCachedPasswordsCount() == 2);
      
   }
   
   /**
    * Test {CMD}org.jboss.test.security.helpers.ExecPasswordCmd
    * @throws Exception
    */
   public void testCmdPassword() throws Exception
   {
      String passwordCmd = buildExtCommand("CMD", ',');
      if (!Util.isPasswordCommand(passwordCmd)) {
         fail(passwordCmd + " should be treated as external password with comand");
      }
      log.info("Executing password command:" + passwordCmd);
      char[] password = Util.loadPassword(passwordCmd);
      assertTrue("password3", Arrays.equals(password, "password3".toCharArray()));

      String passwordCmdWithParam = passwordCmd + ",Parameter 1";
      log.info("Executing password command:" + passwordCmdWithParam);
      password = Util.loadPassword(passwordCmdWithParam);
      assertTrue("passwordParameter 1", Arrays.equals(password, "passwordParameter 1".toCharArray()));

      passwordCmdWithParam = passwordCmd + ",Parameter\\,1";
      log.info("Executing password command:" + passwordCmdWithParam);
      password = Util.loadPassword(passwordCmdWithParam);
      assertTrue("passwordParameter,1", Arrays.equals(password, "passwordParameter,1".toCharArray()));

      String passwordCmdWithTwoParams = passwordCmd + ",Parameter,1";
      log.info("Executing password command:" + passwordCmdWithTwoParams);
      password = Util.loadPassword(passwordCmdWithTwoParams);
      assertTrue("passwordParameter", Arrays.equals(new String(password).substring(0, "passwordParameter".length()).toCharArray(), "passwordParameter".toCharArray()));
      assertTrue("passwordParameter", new String(password).substring("passwordParameter".length()).matches("^\\d+$"));
   }

   private String buildExtCommand(String extOption) {
      return buildExtCommand(extOption, ' ');
   }
   
   private String buildExtCommand(String extOption, char delim) {
      // First check for java.exe or java as the binary
      File java = new File(System.getProperty("java.home"), "/bin/java");
      File javaExe = new File(System.getProperty("java.home"), "/bin/java.exe");
      String jre;
      if( java.exists() )
         jre = java.getAbsolutePath();
      else
         jre = javaExe.getAbsolutePath();
      // Build the command to run this jre
      String cmd = jre
      + delim + "-cp" + delim + System.getProperty("java.class.path")
      + delim + "org.jboss.test.security.helpers.ExecPasswordCmd";

      return "{" + extOption +"}"+cmd;
   }

}
