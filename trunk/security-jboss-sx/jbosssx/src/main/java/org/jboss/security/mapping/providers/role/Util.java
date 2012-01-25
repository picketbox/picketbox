/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.mapping.providers.role;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.PrivilegedActionException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import javax.transaction.SystemException;
import javax.transaction.Transaction;
import javax.transaction.TransactionManager;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;

/**
 * Utility class for this package.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 */
public class Util
{

   /** 
    * Utility method which loads the given properties file and returns a
    * Properties object containing the key,value pairs in that file.
    * The properties files should be in the class path as this method looks
    * to the thread context class loader (TCL) to locate the resource. If the
    * TCL is a URLClassLoader the findResource(String) method is first tried.
    * If this fails or the TCL is not a URLClassLoader getResource(String) is
    * tried.
    * @param propertiesName - the name of the properties file resource
    * @param log - the logger used for trace level messages
    * @return the loaded properties file if found
    * @exception java.io.IOException thrown if the properties file cannot be found
    *    or loaded 
    */
   static Properties loadProperties(String propertiesName, Logger log) throws IOException
   {
      boolean trace = log.isTraceEnabled();

      Properties bundle = null;
      ClassLoader loader = SecurityActions.getContextClassLoader();
      URL url = null;
      // First check for local visibility via a URLClassLoader.findResource
      if (loader instanceof URLClassLoader)
      {
         URLClassLoader ucl = (URLClassLoader) loader;
         url = SecurityActions.findResource(ucl, propertiesName);
         if (log.isTraceEnabled())
            log.trace("findResource: " + url);
      }
      // Do a general resource search
      if (url == null)
         url = loader.getResource(propertiesName);
      if (url == null) {
         try {
            url = new URL(propertiesName);
         } catch (MalformedURLException mue) {
            if (trace)
               log.trace("Failed to open properties as URL", mue);
            File tmp = new File(propertiesName);
            if (tmp.exists())
               url = tmp.toURI().toURL();
         }
      }
      if (url == null)
      {
         String msg = "No properties file " + propertiesName + " found";
         throw new IOException(msg);
      }

      if (log.isTraceEnabled())
         log.trace("Properties file=" + url);
      Properties defaults = new Properties();
      bundle = new Properties(defaults);
      InputStream is = null;
      try
      {
         is = SecurityActions.openStream(url);
      }
      catch (PrivilegedActionException e)
      {
         if (trace)
            log.trace("Open stream error", e);
         throw new IOException(e.getLocalizedMessage());
      }
      if (is != null)
      {
         bundle.load(is);
         is.close();
      }
      else
      {
         throw new IOException(ErrorCodes.MISSING_FILE + "Properties file " + propertiesName + " not available");
      }
      if (trace)
         log.debug("Loaded properties, keySet=" + bundle.keySet());

      return bundle;
   }

   /** 
    * Create the set of roles the user belongs to by parsing the roles.properties
    * data for username=role1,role2,...
    * 
    * @param username - name of user
    * @param roleGroup - group containing the user's roles
    * @param roles - the Properties containing the user=roles mappings
    * @param log - logger
    * @return Group[] containing the sets of roles
    */
   static void addRolesToGroup(String username, RoleGroup roleGroup, Properties roles, Logger log)
   {
      boolean trace = log.isTraceEnabled();
      String[] roleNames = null;
      if (roles.containsKey(username))
      {
         String value = roles.getProperty(username);
         if (trace)
            log.trace("Adding to RoleGroup: " + value);
         roleNames = parseRoles(value);
      }
      if (roleNames != null)
      {
         for (int i = 0; i < roleNames.length; i++)
         {
            roleGroup.addRole(new SimpleRole(roleNames[i]));
         }
      }
   }

   /** 
    * Parse the comma delimited roles names given by value
    *
    * @param roles - the comma delimited role names.
    */
   static String[] parseRoles(String roles)
   {
      return roles.split(",");
   }

   /**
    * Create the set of roles the user belongs to by querying a database
    * 
    * @param username - name of the user
    * @param roleGroup - group containing the user's roles
    * @param dsJndiName - JNDI name of the datasource
    * @param rolesQuery - prepared statement to query
    * @param log - logger
    * @param suspendResume - flag to indicate if transactions should be suspended/resumed
    * @param tm - transaction manager
    */
   static void addRolesToGroup(String username, RoleGroup roleGroup, String dsJndiName, String rolesQuery, Logger log, boolean suspendResume, TransactionManager tm)
   {
      boolean trace = log.isTraceEnabled();
      Connection conn = null;
      PreparedStatement ps = null;
      ResultSet rs = null;

      if (suspendResume)
      {
         if (tm == null)
            throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Transaction Manager is null");
      }
      Transaction tx = null;
      if (suspendResume)
      {
         try
         {
            tx = tm.suspend();
         }
         catch (SystemException e)
         {
            throw new RuntimeException(e);
         }
         if (trace)
            log.trace("suspendAnyTransaction");
      }

      try
      {
         InitialContext ctx = new InitialContext();
         DataSource ds = (DataSource) ctx.lookup(dsJndiName);
         conn = ds.getConnection();
         // Get the user role names
         if (trace)
            log.trace("Excuting query: " + rolesQuery + ", with username: " + username);
         ps = conn.prepareStatement(rolesQuery);
         try
         {
            ps.setString(1, username);
         }
         catch (ArrayIndexOutOfBoundsException ignore)
         {
            // The query may not have any parameters so just try it
         }
         rs = ps.executeQuery();
         if (!rs.next())
         {
            if (trace)
               log.trace("No roles found");
         }
         
         do
         {
            String name = rs.getString(1);
            roleGroup.addRole(new SimpleRole(name));
         }
         while (rs.next());
      }
      catch (NamingException ex)
      {
         throw new IllegalArgumentException(ErrorCodes.PROCESSING_FAILED + "Error looking up DataSource from: " + dsJndiName, ex);
      }
      catch (SQLException ex)
      {
         throw new IllegalArgumentException(ErrorCodes.PROCESSING_FAILED + "Query failed", ex);
      }
      finally
      {
         if (rs != null)
         {
            try
            {
               rs.close();
            }
            catch (SQLException e)
            {
            }
         }
         if (ps != null)
         {
            try
            {
               ps.close();
            }
            catch (SQLException e)
            {
            }
         }
         if (conn != null)
         {
            try
            {
               conn.close();
            }
            catch (Exception ex)
            {
            }
         }
         if (suspendResume)
         {
            try
            {
               tm.resume(tx);
            }
            catch (Exception e)
            {
               throw new RuntimeException(e);
            }
            if (trace)
               log.trace("resumeAnyTransaction");
         }
      }
   }

}
