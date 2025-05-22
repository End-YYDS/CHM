# 測試用Ldap container
## 在背景啟動一個名字叫my-openldap-container的container,並且將初始化設定載入
```shell
docker run --rm -d --name my-openldap-container --env=LDAP_ADMIN_PASSWORD=admin --env=LDAP_DOMAIN=example.com --volume ./ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom -p 389:389  -p 636:636 osixia/openldap:latest --copy-service
```
## 測試openLdap是否開啟成功
```shell
docker exec my-openldap-container ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin
```
