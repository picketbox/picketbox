package org.jboss.test.security.vault;

/**
 * Testing password provider for a Vault keystore.
 *
 * @author <a href="mailto:istudens@redhat.com">Ivo Studensky</a>
 */
public class KeystorePasswordProvider
{
   public char[] toCharArray()
   {
      return "vault22".toCharArray();
   }
}
