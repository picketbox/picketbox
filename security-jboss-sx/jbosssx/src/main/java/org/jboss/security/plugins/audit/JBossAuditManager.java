/*
 * JBoss, the OpenSource J2EE webOS
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */ 
package org.jboss.security.plugins.audit;

import java.security.PrivilegedActionException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.jboss.security.audit.AuditContext;
import org.jboss.security.audit.AuditEvent;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.audit.AuditProvider;
import org.jboss.security.audit.config.AuditProviderEntry;
import org.jboss.security.audit.providers.LogAuditProvider;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuditInfo;
import org.jboss.security.config.SecurityConfiguration; 

/**
 *  Manages a set of AuditContext
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @version $Revision$
 *  @since  Aug 22, 2006
 */
public class JBossAuditManager implements AuditManager
{
   private static Logger log = Logger.getLogger(JBossAuditManager.class);
   
   private static ConcurrentHashMap<String,AuditContext> contexts = new ConcurrentHashMap<String,AuditContext>();
   
   private static AuditContext defaultContext = null;
   
   private static Map<String, Class<?> > clazzMap = new WeakHashMap<String, Class<?>>();
   
   static
   {
      defaultContext = new JBossAuditContext("Default_Context");
      defaultContext.addProvider(new LogAuditProvider()); 
   }

   private String securityDomain;
   
   public JBossAuditManager(String secDomain)
   {
      this.securityDomain = secDomain;
   }
   
   public AuditContext getAuditContext() throws PrivilegedActionException
   {
      AuditContext ac = (AuditContext)contexts.get(securityDomain);
      if(ac == null)
      {
         ac = new JBossAuditContext(securityDomain);
         ApplicationPolicy ap = SecurityConfiguration.getApplicationPolicy(securityDomain);
         if(ap != null)
         {
            AuditInfo ai = ap.getAuditInfo();
            if(ai != null)
            {  
               AuditProviderEntry[] apeArr = ai.getAuditProviderEntry();
               List<AuditProviderEntry> list = Arrays.asList(apeArr);
               for(AuditProviderEntry ape:list)
               {
                  String pname = ape.getName();
                  try
                  {
                     Class<?> clazz = clazzMap.get(pname);
                     if( clazz == null )
                     {
                        clazz = SecurityActions.loadClass(pname);
                        clazzMap.put(pname, clazz); 
                     }
                     
                     ac.addProvider((AuditProvider) clazz.newInstance());
                  }
                  catch (Exception e)
                  {
                     throw new RuntimeException(e);
                  } 
               }
            }
         }
      }
      if(ac == null)
      {
         if(log.isTraceEnabled())
            log.trace("No audit Context found for "+securityDomain+" ; defaulting to"
                  + " audit context for other");
         ac = defaultContext;
      }
      return ac;
   }
   
   public static AuditContext getAuditContext(String securityDomain)
   {
      AuditContext ac = (AuditContext)contexts.get(securityDomain);
      if(ac == null)
         ac = defaultContext;
      return ac;
   } 
   
   public static void addAuditContext(String securityDomain, AuditContext ac)
   {
      contexts.put(securityDomain, ac);
   }

   public void audit(AuditEvent ae)
   {
      AuditContext ac = null;
      try
      {
         ac = getAuditContext();
      }
      catch (PrivilegedActionException e)
      {
        throw new RuntimeException(e);
      }
      ac.audit(ae); 
      //Provide default JBoss trace logging
      if(ac !=  defaultContext)
      {
         defaultContext.audit(ae);
      }
   }

   public String getSecurityDomain()
   { 
      return this.securityDomain;
   }
}
