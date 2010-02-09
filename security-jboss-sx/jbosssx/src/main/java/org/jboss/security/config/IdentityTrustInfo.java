/*
 * JBoss, the OpenSource J2EE webOS
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.security.config;

import org.jboss.security.identitytrust.config.IdentityTrustModuleEntry;

/**
 *  Identity Trust Info
 *  @author <a href="mailto:Anil.Saldhana@redhat.com">Anil Saldhana</a>
 *  @version $Revision$
 *  @since  July 25, 2007
 */
public class IdentityTrustInfo extends BaseSecurityInfo<IdentityTrustModuleEntry>
{  
   public IdentityTrustInfo(String name)
   { 
      super(name);
   } 
   
   public IdentityTrustModuleEntry[] getIdentityTrustModuleEntry()
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission(GET_CONFIG_ENTRY_PERM); 
      IdentityTrustModuleEntry[] entries = new IdentityTrustModuleEntry[moduleEntries.size()];
      moduleEntries.toArray(entries);
      return entries;
   }

   @Override
   protected BaseSecurityInfo<IdentityTrustModuleEntry> create(String name)
   { 
      return new IdentityTrustInfo(name);
   } 
}