use crate::{error::DhcpError, IpPool, LZone, ZoneInfo};
use chm_grpc::dhcp::Zone;
use sqlx::{QueryBuilder, Sqlite, SqlitePool, Transaction};
use tokio::sync::OnceCell;

pub static GLOBAL_DB: OnceCell<Db> = OnceCell::const_new();

pub struct Db {
    db_path:         String,
    max_connections: u32,
    timeout:         u64,
    pool:            OnceCell<SqlitePool>,
}
type DbResult<T> = Result<T, DhcpError>;
impl Db {
    pub const fn new(db_path: String, max_connections: u32, timeout: u64) -> Self {
        Self { db_path, max_connections, timeout, pool: OnceCell::const_new() }
    }
    async fn init_pool(&self) -> DbResult<SqlitePool> {
        let timeout_string = self.timeout.to_string();
        let connect_opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&self.db_path)
            .create_if_missing(true)
            .pragma("auto_vacuum", "FULL")
            .pragma("synchronous", "NORMAL")
            .pragma("busy_timeout", timeout_string)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool: SqlitePool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(self.max_connections)
            .acquire_timeout(std::time::Duration::from_secs(self.timeout))
            .connect_with(connect_opts)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(pool)
    }
    pub async fn pool(&self) -> DbResult<&SqlitePool> {
        self.pool.get_or_try_init(|| async { self.init_pool().await }).await
    }
    pub async fn is_zone_exist(&self, zone_name: &str) -> DbResult<bool> {
        let pool = self.pool().await?;
        let record = sqlx::query!("SELECT id FROM zones WHERE name = ?", zone_name)
            .fetch_optional(pool)
            .await?;
        Ok(record.is_some())
    }
    pub async fn is_ip_conflict(&self, ip_list_json: String) -> DbResult<(bool, Vec<String>)> {
        let pool = self.pool().await?;
        let existing_conflicts = sqlx::query!(
            "SELECT ip FROM ip_pools WHERE ip IN (SELECT value FROM json_each(?))",
            ip_list_json
        )
        .fetch_all(pool)
        .await?;
        let has_conflict = !existing_conflicts.is_empty();
        let conflicts = existing_conflicts.into_iter().map(|r| r.ip).collect();
        Ok((has_conflict, conflicts))
    }
    pub async fn insert_zone(&self, zone: LZone) -> DbResult<i64> {
        let pool = self.pool().await?;
        let mut tx: Transaction<'_, Sqlite> = pool.begin().await?;
        let result: sqlx::sqlite::SqliteQueryResult = sqlx::query!(
            "INSERT INTO zones (name, vni, network, broadcast, subnet_mask) VALUES (?, ?, ?, ?, ?)",
            zone.name,
            zone.vni,
            zone.network,
            zone.broadcast,
            zone.subnet_mask
        )
        .execute(tx.as_mut())
        .await?;

        let zone_id = result.last_insert_rowid();
        tx.commit().await?;
        Ok(zone_id)
    }
    pub async fn insert_ip_pool(
        &self,
        zone_id: i64,
        ip_string: String,
        can_ignore: bool,
    ) -> DbResult<()> {
        let pool = self.pool().await?;
        let mut tx: Transaction<'_, Sqlite> = pool.begin().await?;
        if can_ignore {
            sqlx::query!(
                "INSERT OR IGNORE INTO ip_pools (zone_id, ip) VALUES (?, ?)",
                zone_id,
                ip_string
            )
            .execute(tx.as_mut())
            .await
            .map_err(DhcpError::DatabaseError)?;
        } else {
            sqlx::query!("INSERT INTO ip_pools (zone_id, ip) VALUES (?, ?)", zone_id, ip_string)
                .execute(tx.as_mut())
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn get_zone_id(&self, zone_name: &str) -> DbResult<i64> {
        let pool = self.pool().await?;
        let record =
            sqlx::query!("SELECT id FROM zones WHERE name = ?", zone_name).fetch_one(pool).await?;
        Ok(record.id.expect("Zone ID should not be null"))
    }
    pub async fn zone_exists(&self, zone_name: &str) -> DbResult<bool> {
        let pool = self.pool().await?;
        let record = sqlx::query!("SELECT id FROM zones WHERE name = ?", zone_name)
            .fetch_optional(pool)
            .await?;
        Ok(record.is_some())
    }
    pub async fn get_zone_info_by_id(&self, zone_id: i64) -> DbResult<Option<IpPool>> {
        let pool = self.pool().await?;
        let record = sqlx::query_as_unchecked!(
            IpPool,
            "SELECT id, zone_id, ip FROM ip_pools WHERE zone_id = ? LIMIT 1",
            zone_id
        )
        .fetch_optional(pool)
        .await?;
        Ok(record)
    }
    pub async fn remove_ip_pools(&self, ip: Option<IpPool>) -> DbResult<String> {
        let pool = self.pool().await?;
        if let Some(ip_rec) = ip {
            let mut tx = pool.begin().await?;
            sqlx::query!("DELETE FROM ip_pools WHERE id = ?", ip_rec.id)
                .execute(tx.as_mut())
                .await?;
            tx.commit().await?;
            Ok(ip_rec.ip)
        } else {
            Err(DhcpError::NoAvailableIps)
        }
    }
    pub async fn remove_zone_by_name(&self, zone_name: &str) -> DbResult<()> {
        let pool = self.pool().await?;
        let mut tx: Transaction<'_, Sqlite> = pool.begin().await?;
        sqlx::query!("DELETE FROM zones WHERE name = ?", zone_name).execute(tx.as_mut()).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn get_all_zones_info(&self) -> DbResult<Vec<Zone>> {
        let pool = self.pool().await?;
        let records = sqlx::query!("SELECT name, vni FROM zones").fetch_all(pool).await?;
        let zones: Vec<Zone> =
            records.into_iter().map(|r| Zone { name: r.name, vni: r.vni }).collect();
        Ok(zones)
    }
    pub async fn get_ip_by_zone_id(&self, zone_id: i64) -> DbResult<Vec<String>> {
        let pool = self.pool().await?;
        let records = sqlx::query!("SELECT ip FROM ip_pools WHERE zone_id = ?", zone_id)
            .fetch_all(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;
        let ips = records.into_iter().map(|r| r.ip).collect();
        Ok(ips)
    }
    pub async fn add_pc_to_zone(
        &self,
        zone_id: i64,
        pc_uuid: &str,
        ignore: bool,
    ) -> DbResult<bool> {
        let pool = self.pool().await?;
        let mut tx = pool.begin().await?;
        let sql = if ignore {
            "INSERT OR IGNORE INTO zone_pcs (zone_id, pc_uuid) VALUES (?, ?)"
        } else {
            "INSERT INTO zone_pcs (zone_id, pc_uuid) VALUES (?, ?)"
        };
        let result = sqlx::query(sql).bind(zone_id).bind(pc_uuid).execute(tx.as_mut()).await?;
        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }
    pub async fn add_pcs_to_zone_bulk(
        &self,
        zone_id: i64,
        pc_uuids: &[String],
        ignore: bool,
    ) -> DbResult<u64> {
        if pc_uuids.is_empty() {
            return Ok(0);
        }
        let pool = self.pool().await?;
        let mut tx = pool.begin().await?;
        let mut qb = QueryBuilder::<Sqlite>::new("INSERT ");
        if ignore {
            qb.push("OR IGNORE ");
        }
        qb.push("INTO zone_pcs (zone_id, pc_uuid) ");
        qb.push_values(pc_uuids, |mut b, uuid| {
            b.push_bind(zone_id).push_bind(uuid);
        });
        let result = qb.build().execute(tx.as_mut()).await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }
    pub async fn remove_pc_from_zone(&self, zone_id: i64, pc_uuid: &str) -> DbResult<u64> {
        let pool = self.pool().await?;
        let mut tx = pool.begin().await?;
        let result = sqlx::query!(
            "DELETE FROM zone_pcs WHERE zone_id = ? AND pc_uuid = ?",
            zone_id,
            pc_uuid
        )
        .execute(tx.as_mut())
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }
    pub async fn list_pcs_in_zone(&self, zone_id: i64) -> DbResult<Vec<String>> {
        let pool = self.pool().await?;
        let rows = sqlx::query!("SELECT pc_uuid FROM zone_pcs WHERE zone_id = ?", zone_id)
            .fetch_all(pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.pc_uuid).collect())
    }
    pub async fn is_pc_in_zone(&self, zone_id: i64, pc_uuid: &str) -> DbResult<bool> {
        let pool = self.pool().await?;
        let row = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM zone_pcs WHERE zone_id = ? AND pc_uuid = ?)",
        )
        .bind(zone_id)
        .bind(pc_uuid)
        .fetch_one(pool)
        .await?;
        Ok(row == 1)
    }
    pub async fn list_zones_by_pc(&self, pc_uuid: &str) -> DbResult<Vec<(i64, String, i64)>> {
        let pool = self.pool().await?;
        let rows = sqlx::query!(
            r#"
        SELECT z.id as "id!", z.name as "name!", z.vni as "vni!"
        FROM zones z
        JOIN zone_pcs zp ON zp.zone_id = z.id
        WHERE zp.pc_uuid = ?
        ORDER BY z.name
        "#,
            pc_uuid
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|r| (r.id, r.name, r.vni)).collect())
    }
    pub async fn count_pcs_in_zone(&self, zone_id: i64) -> DbResult<i64> {
        let pool = self.pool().await?;
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM zone_pcs WHERE zone_id = ?")
            .bind(zone_id)
            .fetch_one(pool)
            .await?;
        Ok(count)
    }
    pub async fn insert_ip_pools_bulk(
        &self,
        zone_id: i64,
        ips: &[String],
        ignore: bool,
    ) -> DbResult<u64> {
        if ips.is_empty() {
            return Ok(0);
        }
        let pool = self.pool().await?;
        let mut tx = pool.begin().await?;

        let mut qb = QueryBuilder::<Sqlite>::new("INSERT ");
        if ignore {
            qb.push("OR IGNORE ");
        }
        qb.push("INTO ip_pools (zone_id, ip) ");
        qb.push_values(ips, |mut b, ip| {
            b.push_bind(zone_id).push_bind(ip);
        });

        let result = qb.build().execute(tx.as_mut()).await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }
    /// vni 是否存在
    pub async fn zone_exists_by_vni(&self, vni: i64) -> DbResult<bool> {
        let pool = self.pool().await?;
        let exists =
            sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM zones WHERE vni = ?)")
                .bind(vni)
                .fetch_one(pool)
                .await?;
        Ok(exists == 1)
    }

    /// 透過 vni 取 zone_id（若不存在回傳 Err）
    pub async fn get_zone_id_by_vni(&self, vni: i64) -> DbResult<i64> {
        let pool = self.pool().await?;
        let rec = sqlx::query!("SELECT id FROM zones WHERE vni = ?", vni).fetch_one(pool).await?;
        Ok(rec.id.expect("zones.id should not be NULL"))
    }

    /// 透過 vni 取得該 zone 的所有 IP 清單
    pub async fn get_ips_by_vni(&self, vni: i64) -> DbResult<Vec<String>> {
        let pool = self.pool().await?;
        let rows = sqlx::query!(
            r#"SELECT ip FROM ip_pools WHERE zone_id = (SELECT id FROM zones WHERE vni = ?)"#,
            vni
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.ip).collect())
    }

    /// 透過 vni 取得該 zone 的所有 PC UUID 清單
    pub async fn list_pcs_by_vni(&self, vni: i64) -> DbResult<Vec<String>> {
        let pool = self.pool().await?;
        let rows = sqlx::query!(
            r#"
            SELECT zp.pc_uuid
            FROM zone_pcs AS zp
            JOIN zones AS z ON z.id = zp.zone_id
            WHERE z.vni = ?
            ORDER BY zp.pc_uuid
            "#,
            vni
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.pc_uuid).collect())
    }

    /// 透過 vni 把zone row+IPs+PCs一次組好（不存在則回傳 Ok(None)）
    pub async fn get_zone_info_by_vni(&self, vni: i64) -> DbResult<Option<ZoneInfo>> {
        let pool = self.pool().await?;
        let row = sqlx::query!(
            r#"
            SELECT
                id          AS "id!",
                name        AS "name!",
                vni         AS "vni!",
                network     AS "network!",
                broadcast   AS "broadcast!",
                subnet_mask AS "subnet_mask!"
            FROM zones
            WHERE vni = ?
            "#,
            vni
        )
        .fetch_optional(pool)
        .await?;

        let Some(z) = row else {
            return Ok(None);
        };
        let ips = self.get_ips_by_vni(vni).await?;
        let pcs = self.list_pcs_by_vni(vni).await?;

        let info = ZoneInfo {
            id: z.id,
            name: z.name,
            vni: z.vni,
            network: z.network,
            broadcast: z.broadcast,
            subnet_mask: z.subnet_mask,
            ips,
            pcs,
        };
        Ok(Some(info))
    }
    /// 透過 VNI 更新 Zone 名稱。
    /// 回傳受影響列數（0 = VNI 不存在；1 = 成功更新）。
    pub async fn update_zone_name_by_vni(&self, vni: i64, new_name: &str) -> DbResult<u64> {
        let pool = self.pool().await?;
        let mut tx = pool.begin().await?;
        let res = sqlx::query!(
            r#"UPDATE zones SET name = ? WHERE id = (SELECT id FROM zones WHERE vni = ?)"#,
            new_name,
            vni
        )
        .execute(tx.as_mut())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return DhcpError::ZoneExists(new_name.to_string());
                }
            }
            DhcpError::from(e)
        })?;
        tx.commit().await?;
        Ok(res.rows_affected())
    }
}

pub async fn get_db() -> &'static Db {
    let (db_path, max_connections, timeout) = crate::globals::GlobalConfig::with(|cfg| {
        let db_path = cfg.extend.db.store_path.clone().display().to_string();
        let max_connections = cfg.extend.db.max_connections;
        let timeout = cfg.extend.db.timeout;
        (db_path, max_connections, timeout)
    });
    GLOBAL_DB.get_or_init(|| async { Db::new(db_path, max_connections, timeout) }).await
}
