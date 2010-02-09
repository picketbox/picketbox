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
package org.jboss.security.auth.login;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Set;

import org.jboss.security.auth.spi.UsersObjectModelFactory;
import org.jboss.security.authorization.config.SecurityConfigObjectModelFactory;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.PolicyConfig;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.xb.binding.Unmarshaller;
import org.jboss.xb.binding.UnmarshallerFactory;

/**
 * Parsing utility using JBossXB
 * @author Anil.Saldhana@redhat.com
 * @since May 30, 2008
 */
public class JBossXBParsingUtil
{
   private XMLLoginConfigImpl xmlConfig = XMLLoginConfigImpl.getInstance();
   
   public void parse(URL loginConfigURL, ArrayList<String> configNames) throws Exception
   {
      LoginConfigObjectModelFactory lcomf = new SecurityConfigObjectModelFactory();
      UsersObjectModelFactory uomf = new UsersObjectModelFactory();

      InputStreamReader xmlReader = loadURL(loginConfigURL);
      Unmarshaller unmarshaller = UnmarshallerFactory.newInstance().newUnmarshaller();
      unmarshaller.mapFactoryToNamespace(uomf, "http://www.jboss.org/j2ee/schemas/XMLLoginModule");
      Object root = null;
      PolicyConfig config = (PolicyConfig) unmarshaller.unmarshal(xmlReader, lcomf, root);
      Set<String> cnames = config.getConfigNames();
      configNames.addAll(cnames);
      xmlConfig.copy(config); 
      
      // Add the config to SecurityConfiguration
      for (String cname : cnames)
      {
         ApplicationPolicy ap = config.get(cname);
         SecurityConfiguration.addApplicationPolicy(ap);
         handleJASPIDelegation(ap);
      }

   }
   
   private void handleJASPIDelegation(ApplicationPolicy aPolicy)
   {
      BaseAuthenticationInfo bai = aPolicy.getAuthenticationInfo();
      if (bai instanceof JASPIAuthenticationInfo)
      {
         JASPIAuthenticationInfo jai = (JASPIAuthenticationInfo) bai;
         LoginModuleStackHolder[] lmsharr = jai.getLoginModuleStackHolder();
         for (LoginModuleStackHolder lmsh : lmsharr)
         {
            xmlConfig.addAppConfig(lmsh.getName(), lmsh.getAppConfigurationEntry());
         }
      }
   }
   
   private InputStreamReader loadURL(URL configURL) throws IOException
   {
      InputStream is = configURL.openStream();
      if (is == null)
         throw new IOException("Failed to obtain InputStream from url: " + configURL);
      InputStreamReader xmlReader = new InputStreamReader(is);
      return xmlReader;
   }
}