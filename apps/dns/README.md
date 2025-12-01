# CHM DNS初始配置
## ENV 配置
```shell
export DATABASE_URL=postgresql://<username>:<password>@<host>:<port>/<database>
```

## 透過Docker建立資料庫
```shell
./db.sh
```

### 進入Docker的CLi
```shell
docker exec -it CHM-DNS /bin/bash
```

### 進入psql
```shell
psql -U chm -d dns
```
