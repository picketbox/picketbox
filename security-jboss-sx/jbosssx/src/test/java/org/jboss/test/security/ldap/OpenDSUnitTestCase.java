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
package org.jboss.test.security.ldap;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import junit.framework.TestCase;
import org.opends.server.core.DirectoryServer;

/**
 *  Test Basic OpenDS functionality
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 23, 2007 
 *  @version $Revision$
 */
public class OpenDSUnitTestCase extends TestCase
{   
   protected String serverHost;
   protected String port = "10389";
   protected String adminPW = "password";
   protected String dn = "dc=jboss,dc=org";
   protected String adminDN = "cn=Directory Manager";
   protected OpenDSUtil util = new OpenDSUtil();
   
   /**
    * Use a different value for the system property on 
    * a JVM that is not shipped by Sun
    */
   protected String ldapCtxFactory = System.getProperty("ldapctx.factory",
         "com.sun.jndi.ldap.LdapCtxFactory");

   protected String baseDir = System.getProperty("user.dir");
   protected String fs = File.separator;
   
   //System property when running in eclipse (-Declipse=jbosssx/ )
   private String eclipsePath = System.getProperty("eclipse","");
   
   //protected String targetDir = eclipsePath + "target" + fs + "test-classes" + fs + getName() + fs;
   protected String targetDir = eclipsePath + "target" + fs + "test-classes" + fs;
   protected String openDSDir =   targetDir + "opends" ;
   
   protected OpenDS opends = null;
   
   public OpenDSUnitTestCase(String name)
   {
      super(name); 
   }

   @Override
   protected void setUp() throws Exception
   {   
      super.setUp();
      //Ensure openDSDir exists and recycle opends db dir
      File openDSDirFile = new File(openDSDir);
      if(openDSDirFile.exists())
      {
         File dbDir = new File(openDSDir, "db");
         assertTrue("Deletion of opendsDir db success", recursiveDeleteDir(dbDir));
         assertTrue("Creation of opendsDir DB success", dbDir.mkdirs());
      }

      serverHost = "localhost";
      
      opends = new OpenDS();

      if (opends.isRunning()) {
         opends.stopServer();
      }
      opends.intialize(openDSDir);
      opends.startServer();
      assertTrue(opends.isRunning()); 
   }
   
   @Override
   protected void tearDown() throws Exception
   {
      super.tearDown(); 
      assertTrue("DS is running",opends.isRunning());
      shutdown();
      assertFalse("DS is not running",opends.isRunning());
   }
   
   public void testLDAPAddDelete() throws Exception
   {
      String fileName = targetDir + "ldap" + fs + "example1.ldif";
      boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURI().toURL());
      assertTrue(op);
      
      DirContext dc = null;
      NamingEnumeration<SearchResult> ne = null;
      try
      {
         dc = this.getDirContext();
         assertNotNull("DirContext exists?", dc);  

         //Use JDK JNDI code for a search
         SearchControls sc = new SearchControls();
         sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
         ne = dc.search(dn, "(objectclass=*)", sc);
         while (ne.hasMore()) 
         { 
            SearchResult sr = ne.next(); 
            assertTrue("Search Result exists?", sr != null); 
         }

         //We will delete the DIT just created
         assertTrue(util.deleteDNRecursively(serverHost, port, adminDN, adminPW, dn)); 

         assertFalse("The DIT does not exist", util.existsDN(serverHost, port, dn));
      }
      catch(Exception e)
      {
         System.err.println("Error in searching:");
         e.printStackTrace();
      } 

      finally
      {
         if(ne != null)
            ne.close();
         if(dc != null)
           dc.close(); 
      }  
   }
    
   protected void shutdown() throws Exception
   { 
      //Check if the server is running
      if(opends.isRunning())
         opends.stopServer();
   }
   
   private DirContext getDirContext() throws Exception
   {
      String url = "ldap://" + serverHost  + ":" + port;
      Hashtable<String, String> env = new Hashtable<String,String>();
      env.put(Context.INITIAL_CONTEXT_FACTORY, ldapCtxFactory);
      env.put(Context.PROVIDER_URL, url);
      env.put(Context.SECURITY_AUTHENTICATION, "simple");
      env.put(Context.SECURITY_PRINCIPAL, adminDN);
      env.put(Context.SECURITY_CREDENTIALS, adminPW);
      return new InitialDirContext(env);   
   }
   
   private boolean recursiveDeleteDir(File dirPath) throws IOException {
      if( dirPath.exists() )
      {
         File[] files = dirPath.listFiles();
         for (File file : files) {
            if (file.isDirectory()) {
               recursiveDeleteDir(file);
            } else {
               Files.delete(file.toPath());
            }
         }
       }
       if(Files.exists(dirPath.toPath())) {
          Files.delete(dirPath.toPath());
       }

      return true;
   }
}