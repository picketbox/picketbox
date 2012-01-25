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
package org.jboss.security.plugins;

import org.jboss.logging.Logger;

/**
 * Supports the RemoteHostTrustLoginModule and RemoteHostValve, holds the remote host in a thread local.
 * @author Andrew C. Oliver
 * @version $Revision: 0 $
 */
public class HostThreadLocal 
{
   private static Logger log = Logger.getLogger(HostThreadLocal.class);
   private static ThreadLocal<String> host = new ThreadLocal<String>();

   public static String get() 
   {
      if (log.isTraceEnabled()) 
      {
          log.trace("returning "+host.get()+" for tid "+Thread.currentThread().getId());
      }
      return (String)host.get();
   }

   public static void set(String hostVal) 
   {
      if (log.isTraceEnabled()) 
      {
          log.trace("setting "+hostVal+" for tid "+Thread.currentThread().getId());
      }
      host.set(hostVal);
   }

}