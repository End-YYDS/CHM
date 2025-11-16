# 測試用Ldap container

## 使用docker-compose 啟動容器
```yaml
services:
  openldap:
    image: docker.io/osixia/openldap:1.5.0
    container_name: openldap
    hostname: openldap
    restart: unless-stopped
    command: ["--copy-service", "--loglevel", "debug"]
    environment:
      LDAP_ORGANISATION: ${LDAP_ORGANISATION}
      LDAP_DOMAIN: ${LDAP_DOMAIN}
      LDAP_BASE_DN: ${LDAP_BASE_DN}
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD}
      LDAP_CONFIG_PASSWORD: ${LDAP_CONFIG_PASSWORD}
      LDAP_TLS: ${ENABLE_LDAP_TLS}
      LDAP_TLS_VERIFY_CLIENT: ${LDAP_TLS_VERIFY_CLIENT}
      LDAP_TLS_CRT_FILENAME: ${LDAP_TLS_CRT_FILENAME}
      LDAP_TLS_KEY_FILENAME: ${LDAP_TLS_KEY_FILENAME}
      LDAP_TLS_CA_CRT_FILENAME: ${LDAP_TLS_CA_CRT_FILENAME}
      LDAP_REMOVE_CONFIG_AFTER_SETUP: "false"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ./data/slapd/database:/var/lib/ldap
      - ./data/slapd/config:/etc/ldap/slapd.d
      - ./bootstrap/ldif/custom:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
      - ./bootstrap/schema/custom:/container/service/slapd/assets/config/bootstrap/schema/custom:ro
      - ./certs:/container/service/slapd/assets/certs
    healthcheck:
      test: ["CMD", "ldapsearch", "-x", "-H", "ldap://127.0.0.1:389", "-b", "${LDAP_BASE_DN}", "-s", "base"]
      interval: 30s
      timeout: 10s
      retries: 5

  phpldapadmin:
    image: docker.io/osixia/phpldapadmin:0.9.0
    container_name: phpldapadmin
    hostname: phpldapadmin
    restart: unless-stopped
    environment:
      PHPLDAPADMIN_HTTPS: ${PHPLDAPADMIN_HTTPS}
      PHPLDAPADMIN_LDAP_HOSTS: ${PHPLDAPADMIN_LDAP_HOSTS}
    ports:
      - "6443:443"
    depends_on:
      - openldap
    healthcheck:
      test: ["CMD", "curl", "-fsS", "https://127.0.0.1/"]
      interval: 30s
      timeout: 10s
      retries: 5

networks:
  default:
    name: ldapnet

```
### .env file
```conf
LDAP_ORGANISATION="CHM Inc."
LDAP_DOMAIN="chm.com"
LDAP_BASE_DN="dc=chm,dc=com"
LDAP_ADMIN_PASSWORD=""
LDAP_CONFIG_PASSWORD=""
PHPLDAPADMIN_HTTPS=true
PHPLDAPADMIN_LDAP_HOSTS=openldap
ENABLE_LDAP_TLS=false
LDAP_TLS_CRT_FILENAME=
LDAP_TLS_KEY_FILENAME=
LDAP_TLS_CA_CRT_FILENAME=
LDAP_TLS_VERIFY_CLIENT=try   # none|allow|try|demand
```

## 在背景啟動一個名字叫my-openldap-container的container,並且將初始化設定載入

```shell
docker run --rm -d --name my-openldap-container --env=LDAP_ADMIN_PASSWORD=admin --env=LDAP_DOMAIN=example.com --volume ./ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom -p 389:389  -p 636:636 osixia/openldap:latest --copy-service
```

## 測試openLdap是否開啟成功

```shell
docker exec my-openldap-container ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin
```

## 實體PC安裝Ldap

### Server Configuration

#### 安裝Openldap套件

```shell
sudo apt install slapd ldap-utils libargon2-dev -y
```

#### 重新設定slapd

```shell
sudo dpkg-reconfigure slapd
```

#### 測試openLdap是否開啟成功

```shell
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b "dc=chm,dc=com"
```

### Client Configuration

#### 安裝套件

```shell
sudo apt install libnss-ldap libpam-ldap ldap-utils nslcd -y # 先使用nslcd簡易驗證
```

#### 配置/etc/nsswitch.conf

```plaintext
passwd:         files systemd ldap
group:          files systemd ldap
shadow:         files systemd ldap
```

#### 配置/etc/pam.d/common-session

```plaintext
session required pam_mkhomedir.so skel=/etc/skel/ umask=0022
```

## Ldap 指令
### 檢查已載入模組
```shell
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=module{0},cn=config" olcModuleLoad
ldapsearch -x -H ldap://127.0.0.1 \
  -D "cn=admin,cn=config" -W \
  -b cn=config '(objectClass=olcModuleList)' olcModulePath olcModuleLoad

```
### 查看ACL
```shell
ldapsearch -Y EXTERNAL -H ldapi:/// -LLL -b 'olcDatabase={1}mdb,cn=config' olcAccess
```

### 查看資料庫編號
```shell
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config '(olcDatabase=*)' olcDatabase olcSuffix
```
### 載入Admin Config
```shell
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f init_socket.ldif
```
### 載入一般Config
```shell
ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,dc=chm,dc=com" -W -f base_ous.ldif
```

### 載入模組
```shell
ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,cn=config" -W -f {argon_module.ldif}
```

## LdapClient 安裝所需套件(sssd)

### 配置文件
filename: `/etc/sssd/sssd.conf`
```shell
[sssd]
services = nss, pam, sudo, ssh
config_file_version = 2
domains = ldapdomain
debug_level = 9

[nss]
debug_level = 9

[pam]
debug_level = 9
# 可離線快取密碼（網路斷線仍可登入，選配）
offline_credentials_expiration = 0

[domain/ldapdomain]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
sudo_provider = ldap
ldap_uri = ldap://172.16.125.1
ldap_id_use_start_tls = false
ldap_tls_reqcert = never

ldap_search_base = dc=chm,dc=com
ldap_sudo_search_base = ou=Sudoers,dc=chm,dc=com
ldap_user_search_base = ou=Users,dc=chm,dc=com
ldap_group_search_base = ou=Groups,dc=chm,dc=com

ldap_schema = rfc2307
ldap_group_member = memberUid
enumerate = false
override_homedir = /home/%u
fallback_homedir = /home/%u
default_shell = /bin/bash
access_provider = permit
# ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
ldap_default_bind_dn = cn=ldap-reader,ou=Service,dc=chm,dc=com
ldap_default_authtok = password

ldap_user_name = uid
ldap_auth_disable_tls_never_use_in_production = true # 暫時關閉Pam 驗證時需要TLS 憑證

```

### Client清除快取
```shell
sudo systemctl restart sssd
sudo sss_cache -E
sudo -K
```

### Docker/Podman compose
#### 執行指令
```shell
podman compose exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /container/service/slapd/assets/config/bootstrap/ldif/custom/3.ldif
podman compose exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /container/service/slapd/assets/config/bootstrap/ldif/custom/4.ldif
```
