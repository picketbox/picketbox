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
package org.jboss.test.security.ldap;

import java.io.File;

import org.opends.messages.Message;
import org.opends.server.types.DirectoryEnvironmentConfig;
import org.opends.server.util.EmbeddedUtils;

/**
 * Represents the OpenDS LDAP Server
 * @author Anil.Saldhana@redhat.com
 */
public class OpenDS
{
   private String serverRoot = "";
   
   public OpenDS()
   {   
   }
   
   public void intialize(String serverRoot)
   {
      this.serverRoot = serverRoot;
   } 
   
   public void startServer() throws Exception
   {
      DirectoryEnvironmentConfig config = new DirectoryEnvironmentConfig();
      config.setServerRoot(new File(serverRoot));
      config.setForceDaemonThreads(true);
      
      EmbeddedUtils.startServer(config ); 
   }
   
   public void stopServer() throws Exception
   {
      if(EmbeddedUtils.isRunning())
         EmbeddedUtils.stopServer(getClass().getName(),  Message.EMPTY);     
   }
   
   public boolean isRunning()
   {
      return EmbeddedUtils.isRunning();
   }
}