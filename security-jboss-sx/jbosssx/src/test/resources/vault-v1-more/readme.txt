keystore created:
------------------
keytool -genseckey -alias test -storetype jceks -keystore vault-v1/vault-jceks.keystore -keyalg AES -keysize 128 -storepass secretsecret -keypass secretsecret
keytool -genseckey -alias test2 -storetype jceks -keystore vault-v1/vault-jceks.keystore -keyalg AES -keysize 128 -storepass secretsecret -keypass secretsecret

vault content created (from EAP6.1 dir):
-----------------------------------------
./bin/vault.sh -e vault-v1/vault_data/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr11 -x secret11
./bin/vault.sh -e vault-v1/vault_data/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr12 -x secret12
./bin/vault.sh -e vault-v1/vault_data/ -k vault-v1/vault-jceks.keystore -v test2 -p secretsecret -i 34 -s 12345678 -b vb1 -a attr13 -x secret13
