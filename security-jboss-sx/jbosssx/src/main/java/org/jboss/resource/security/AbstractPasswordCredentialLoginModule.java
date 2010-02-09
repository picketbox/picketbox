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
package org.jboss.resource.security;

import java.util.Map;

import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.resource.spi.ManagedConnectionFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.logging.Logger;
import org.jboss.security.util.MBeanServerLocator;
import org.jboss.security.auth.spi.AbstractServerLoginModule;


/** A base login module that provides access to the ManagedConnectionFactory
 * needed by the PasswordCredential.
 * 
 * @see javax.resource.spi.security.PasswordCredential
 *
 * @author <a href="mailto:d_jencks@users.sourceforge.net">David Jencks</a>
 * @author Scott.Stark@jboss.org
 * @version $Revision: 71545 $
 */

@SuppressWarnings("unchecked")
public abstract class AbstractPasswordCredentialLoginModule
   extends AbstractServerLoginModule
{
   private static final Logger log = Logger.getLogger(AbstractPasswordCredentialLoginModule.class);
   private MBeanServer server;
   private ObjectName managedConnectionFactoryName;
   private ManagedConnectionFactory mcf;
   /** A flag that allows a missing MCF service to be ignored */
   private Boolean ignoreMissigingMCF;

   public AbstractPasswordCredentialLoginModule()
   {
      
   }

   public void initialize(Subject subject, CallbackHandler handler, Map sharedState, Map options)
   {
      super.initialize(subject, handler, sharedState, options);
      String name = (String) options.get("managedConnectionFactoryName");
      try
      {
         managedConnectionFactoryName = new ObjectName(name);
      }
      catch (MalformedObjectNameException mone)
      {
         throw new IllegalArgumentException("Malformed ObjectName: " + name);
      }

      if (managedConnectionFactoryName == null)
      {
         throw new IllegalArgumentException("Must supply a managedConnectionFactoryName!");
      }
      Object flag = options.get("ignoreMissigingMCF");
      if( flag instanceof Boolean )
         ignoreMissigingMCF = (Boolean) flag;
      else if( flag != null )
         ignoreMissigingMCF = Boolean.valueOf(flag.toString());
      server = MBeanServerLocator.locateJBoss();
      getMcf();
   }

   /** Return false if there is no mcf, else return super.login(). Override
    * to provide custom authentication.
    * 
    * @return false if there is no mcf, else return super.login().
    * @exception LoginException if an error occurs
    */
   public boolean login() throws LoginException
   {
      if (mcf == null)
      {
         return false;
      }
      return super.login();
   }

   public boolean logout() throws LoginException
   {
      removeCredentials();
      return super.logout();
   }

   protected ManagedConnectionFactory getMcf()
   {
      if (mcf == null)
      {
         try
         {
            mcf = (ManagedConnectionFactory) server.getAttribute(
               managedConnectionFactoryName,
               "ManagedConnectionFactory");
         }
         catch (Exception e)
         {
            log.error("The ConnectionManager mbean: " + managedConnectionFactoryName
               + " specified in a ConfiguredIdentityLoginModule could not be found."
               + " ConnectionFactory will be unusable!", e);
            if( Boolean.TRUE != ignoreMissigingMCF )
            {
               throw new IllegalArgumentException("Managed Connection Factory not found: "
                  + managedConnectionFactoryName);
            }
         } // end of try-catch
         if (log.isTraceEnabled())
         {
            log.trace("mcfname: " + managedConnectionFactoryName);
         }
      } // end of if ()

      return mcf;
   }

   protected MBeanServer getServer()
   {
      return server;
   }

   /** This removes the javax.security.auth.login.name and
    * javax.security.auth.login.password settings from the sharteState map
    * along with any PasswordCredential found in the PrivateCredentials set
    */
   protected void removeCredentials()
   {
      sharedState.remove("javax.security.auth.login.name");
      sharedState.remove("javax.security.auth.login.password");
      SubjectActions.removeCredentials(subject, mcf);
   }

}

