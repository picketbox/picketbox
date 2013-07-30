Keystore creation:
-----------------------------------
keytool -genkey -alias thealias -keystore vault-jks.keystore -keyalg RSA -keysize 1024 -storepass secretsecret -keypass secretsecret -dname "CN=Picketbox vault,OU=picketbox,O=JBoss"


Keystore maked password attribs:
-----------------------------------
<vault>
  <vault-option name="KEYSTORE_URL" value="vault/vault-jks.keystore"/>
  <vault-option name="KEYSTORE_PASSWORD" value="MASK-X6MP2urfgJoRURxC5tsFw"/>
  <vault-option name="KEYSTORE_ALIAS" value="thealias"/>
  <vault-option name="SALT" value="24681359"/>
  <vault-option name="ITERATION_COUNT" value="88"/>
  <vault-option name="ENC_FILE_DIR" value="vault/vault_data/"/>
</vault>


vault content created in 3 sessions:
-----------------------------------
1. interactive session:
vb	attr1	pwd1
vb	attr2	pwd2
vb1	attr1	pwd3
vb2	attr2	pwd4

2. non-interactive session
vb2	attr3	pwd5

3. non-interactive session
vb	attr3	pwd6


