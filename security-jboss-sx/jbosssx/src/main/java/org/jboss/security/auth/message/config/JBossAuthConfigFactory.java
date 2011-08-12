/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security.auth.message.config;
 
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;

//$Id$

/**
 *  Default Authentication Configuration Factory
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 15, 2006 
 *  @version $Revision$
 */
public class JBossAuthConfigFactory extends AuthConfigFactory
{   
   private AuthProviderRegistrationDelegate delegate = null;  
   
   public JBossAuthConfigFactory()
   {   
      delegate = new AuthProviderRegistrationDelegate();
      Map<String,Object> props = new HashMap<String,Object>();
      JBossAuthConfigProvider provider = new JBossAuthConfigProvider(props);
      //register a few default providers for the layers
      delegate.registerConfigProvider(provider, "HTTP", " ", "Default Provider");  
      delegate.registerConfigProvider(provider, "HttpServlet", " ", "Default Provider"); 
   }
   
   /**
    * @see AuthConfigFactory#detachListener(RegistrationListener, String, String)
    */
   public String[] detachListener(RegistrationListener listener, String layer, 
         String appContext)
   { 
      return delegate.detachListener(listener,layer,appContext);
   }
 
   /**
    * @see AuthConfigFactory#getConfigProvider(String, String, RegistrationListener)
    */
   public AuthConfigProvider getConfigProvider(String layer, String appContext, 
          RegistrationListener listener)
   { 
      return delegate.getConfigProvider(layer, appContext, listener);
   }
 
   /**
    * @see AuthConfigFactory#getRegistrationContext(String)
    */
   public RegistrationContext getRegistrationContext(String registrationID)
   { 
      return delegate.getRegistrationContext(registrationID);
   }
 
   /**
    * @see AuthConfigFactory#getRegistrationIDs(AuthConfigProvider)
    */
   public String[] getRegistrationIDs(AuthConfigProvider provider)
   { 
      return delegate.getRegistrationIDs(provider);
   }
 
   /**
    * @see AuthConfigFactory#refresh()
    */
   public void refresh() throws AuthException, SecurityException
   { 
   }
 
   /**
    * @see AuthConfigFactory#registerConfigProvider(String, Map, String, String, String)
    */ 
   @SuppressWarnings("rawtypes")
   public String registerConfigProvider(String className, Map properties, 
         String layer, String appContext, String description)
   throws AuthException, SecurityException
   { 
      return delegate.registerConfigProvider(className, properties, 
           layer,  appContext,  description);
   }
 
   /**
    * @see AuthConfigFactory#removeRegistration(String)
    */
   public boolean removeRegistration(String registrationID)
   { 
      return delegate.removeRegistration(registrationID);
   }

   @Override
   public String registerConfigProvider(AuthConfigProvider provider,
         String layer,  String appContext,  String description)
   { 
      return delegate.registerConfigProvider(provider, layer, appContext, description);
   } 
}