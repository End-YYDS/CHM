use crate::ConResult;
use chm_grpc::{
    common::{ResponseResult, ResponseType},
    dhcp::{
        dhcp_service_client::DhcpServiceClient, AddPcToZoneByVniRequest, AddPcToZoneRequest,
        PcIdentifier, RemovePcFromZoneByVniRequest, UpdateZoneNameByVniRequest, VniIdentifier,
        Zone, ZoneDetail, ZoneIdentifier,
    },
    tonic::transport::Channel,
};
use std::net::IpAddr;

/// DHCP gRPC 客戶端封裝。
///
/// 提供與 DHCP Server 互動的高階方法，包含：
/// - Zone 管理（建立、刪除、查詢）
/// - IP 池操作（分配、釋放、列出）
/// - Zone ↔ PC 關聯（新增、移除、查詢）
///
/// 所有方法皆回傳 `ConResult<T>`。
#[derive(Debug, Clone)]
pub struct ClientDhcp {
    client:  DhcpServiceClient<Channel>,
    channel: Channel,
}

impl ClientDhcp {
    /// 建立 DHCP 客戶端連線實例。
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 DHCP 客戶端...");
        let client = DhcpServiceClient::new(channel.clone());
        tracing::info!("DHCP 客戶端已建立");
        Self { client, channel }
    }
    /// 取得 gRPC client 實例
    pub fn get_client(&self) -> DhcpServiceClient<Channel> {
        self.client.clone()
    }
    /// 取得底層通道（Channel），可用於重建或分享連線。
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    /// 判斷 `ResponseResult` 是否為成功（`ResponseType::Ok`）。
    #[inline]
    fn is_ok(resp: &ResponseResult) -> bool {
        matches!(ResponseType::try_from(resp.r#type), Ok(ResponseType::Ok))
    }
    /// 建立新的 DHCP Zone。
    ///
    /// # 參數
    /// * `zone_name` - Zone 名稱。
    /// * `vni` - 該 Zone 對應的虛擬網路 ID。
    /// * `cidr` - CIDR 格式的網段（例如 `"192.168.0.0/24"`）。
    ///
    /// # 回傳
    /// 成功建立時回傳 `true`。
    pub async fn create_zone(&self, zone_name: String, vni: i64, cidr: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::CreateZoneRequest { zone_name, vni, cidr };
        let response = client
            .create_zone(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ret = response.message.contains("successfully");
        Ok(ret)
    }
    /// 向指定的 Zone 分配一個可用的 IP。
    ///
    /// # 回傳
    /// 成功時返回已分配的 IP 位址（字串格式）。
    pub async fn allocate_ip(&self, zone_name: String) -> ConResult<String> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::AllocateIpRequest { zone_name };
        let response = client
            .allocate_ip(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(response.ip)
    }
    /// 將 IP 歸還至指定的 Zone。
    ///
    /// # 回傳
    /// 成功釋放回傳 `true`。
    pub async fn release_ip(&self, zone_name: String, ip: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::ReleaseIpRequest { zone_name, ip };
        let response = client
            .release_ip(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ret = response.message.contains("released");
        Ok(ret)
    }
    /// 刪除指定的 DHCP Zone。
    ///
    /// # 回傳
    /// Zone 成功刪除回傳 `true`。
    pub async fn delete_zone(&self, zone_name: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::DeleteZoneRequest { zone_name };
        let response = client
            .delete_zone(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ret = response.message.contains("deleted");
        Ok(ret)
    }
    /// 列出所有已存在的 DHCP Zones。
    ///
    /// # 回傳
    /// `Vec<Zone>`，包含每個 zone 的名稱與 VNI。
    pub async fn list_zones(&self) -> ConResult<Vec<Zone>> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::Empty {};
        let response = client
            .list_zones(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(response.zones)
    }
    /// 取得指定 Zone 內的所有可用 IP。
    ///
    /// # 回傳
    /// `Vec<IpAddr>`，包含所有目前可分配的 IP。
    pub async fn list_available_ips(&self, zone_name: String) -> ConResult<Vec<IpAddr>> {
        let mut client = self.get_client();
        let request = ZoneIdentifier { zone_name };
        let response = client
            .list_available_ips(request)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ips: Vec<IpAddr> =
            response.ips.into_iter().filter_map(|ip_str| ip_str.parse::<IpAddr>().ok()).collect();
        Ok(ips)
    }
    /// 將 PC(UUID) 加入指定 Zone。
    ///
    /// # 回傳
    /// * `true` - 新增成功或已存在。
    /// * `false` - 操作失敗（ResponseType = ERR）。
    pub async fn add_pc_to_zone(&self, zone_name: String, pc_uuid: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let req = AddPcToZoneRequest { zone_name, pc_uuid };
        let resp = client
            .add_pc_to_zone(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(Self::is_ok(&resp))
    }
    /// 從 Zone 移除指定 PC(UUID)。
    ///
    /// # 回傳
    /// * `true` - 成功移除。
    /// * `false` - 該 PC 不存在於該 Zone。
    pub async fn remove_pc_from_zone(&self, zone_name: String, pc_uuid: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let req = chm_grpc::dhcp::RemovePcFromZoneRequest { zone_name, pc_uuid };
        let resp = client
            .remove_pc_from_zone(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(Self::is_ok(&resp))
    }
    /// 列出某個 Zone 內所有 PC(UUID)。
    ///
    /// # 回傳
    /// `Vec<String>` - PC UUID 清單。
    pub async fn list_pcs_in_zone(&self, zone_name: &str) -> ConResult<Vec<String>> {
        let mut client = self.get_client();
        let zone_name = zone_name.to_string();
        let req = ZoneIdentifier { zone_name };
        let resp = client
            .list_pcs_in_zone(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(resp.pcs)
    }
    /// 反查某台 PC 所屬的所有 Zone。
    ///
    /// # 回傳
    /// `Vec<Zone>` - 該 PC 參與的所有 Zone。
    pub async fn list_zones_by_pc(&self, pc_uuid: String) -> ConResult<Vec<Zone>> {
        let mut client = self.get_client();
        let req = PcIdentifier { pc_uuid };
        let resp = client
            .list_zones_by_pc(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(resp.zones)
    }

    /// 依 VNI 取得完整的 Zone 明細（含 network/broadcast/mask、IPs、PC UUIDs）
    pub async fn get_zone_detail_by_vni(&self, vni: i64) -> ConResult<ZoneDetail> {
        let mut client = self.get_client();
        let req = VniIdentifier { vni };
        let resp = client
            .get_zone_detail_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(resp)
    }

    /// 依 VNI 取得目前可用的 IP（尚在 ip_pools 內的 IP）
    ///
    /// # 回傳
    /// `Vec<IpAddr>`：成功解析的 IP 位址集合（無法解析者會被略過）
    pub async fn list_available_ips_by_vni(&self, vni: i64) -> ConResult<Vec<IpAddr>> {
        let mut client = self.get_client();
        let req = VniIdentifier { vni };
        let resp = client
            .list_available_ips_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ips = resp.ips.into_iter().filter_map(|s| s.parse::<IpAddr>().ok()).collect();
        Ok(ips)
    }

    /// 將 PC(UUID) 加入指定 VNI 的 Zone。
    ///
    /// # 回傳
    /// * `true`：新增成功或已存在
    /// * `false`：操作失敗（`ResponseType::Err`）
    pub async fn add_pc_to_zone_by_vni(&self, vni: i64, pc_uuid: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let req = AddPcToZoneByVniRequest { vni, pc_uuid };
        let resp = client
            .add_pc_to_zone_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(Self::is_ok(&resp))
    }

    /// 從指定 VNI 的 Zone 移除 PC(UUID)。
    ///
    /// # 回傳
    /// * `true`：成功移除
    /// * `false`：該 PC 不存在於該 Zone
    pub async fn remove_pc_from_zone_by_vni(&self, vni: i64, pc_uuid: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let req = RemovePcFromZoneByVniRequest { vni, pc_uuid };
        let resp = client
            .remove_pc_from_zone_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(Self::is_ok(&resp))
    }

    /// 依 VNI 列出 Zone 內所有 PC(UUID)
    pub async fn list_pcs_in_zone_by_vni(&self, vni: i64) -> ConResult<Vec<String>> {
        let mut client = self.get_client();
        let req = VniIdentifier { vni };
        let resp = client
            .list_pcs_in_zone_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(resp.pcs)
    }
    /// 透過 VNI 更新 Zone 名稱。
    ///
    /// # 回傳
    /// * `true`：更新成功
    /// * `false`：更新失敗（例如 VNI 不存在或名稱重複）
    pub async fn update_zone_name_by_vni(&self, vni: i64, new_name: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let req = UpdateZoneNameByVniRequest { vni, new_name };
        let resp = client
            .update_zone_name_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok(matches!(ResponseType::try_from(resp.r#type), Ok(ResponseType::Ok)))
    }

    /// 若呼叫端需要訊息字串，可用這個版本取得 (is_ok, message)。
    pub async fn add_pc_to_zone_with_msg(
        &self,
        zone_name: String,
        pc_uuid: String,
    ) -> ConResult<(bool, String)> {
        let mut client = self.get_client();
        let req = AddPcToZoneRequest { zone_name, pc_uuid };
        let resp = client
            .add_pc_to_zone(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok((Self::is_ok(&resp), resp.message))
    }
    /// 與 [`remove_pc_from_zone`] 相同，但會返回 `(是否成功, 訊息文字)`。
    pub async fn remove_pc_from_zone_with_msg(
        &self,
        zone_name: String,
        pc_uuid: String,
    ) -> ConResult<(bool, String)> {
        let mut client = self.get_client();
        let req = chm_grpc::dhcp::RemovePcFromZoneRequest { zone_name, pc_uuid };
        let resp = client
            .remove_pc_from_zone(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok((Self::is_ok(&resp), resp.message))
    }

    /// 與 [`add_pc_to_zone_by_vni`] 相同，但返回 `(是否成功, 訊息文字)`。
    pub async fn add_pc_to_zone_by_vni_with_msg(
        &self,
        vni: i64,
        pc_uuid: String,
    ) -> ConResult<(bool, String)> {
        let mut client = self.get_client();
        let req = AddPcToZoneByVniRequest { vni, pc_uuid };
        let resp = client
            .add_pc_to_zone_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok((Self::is_ok(&resp), resp.message))
    }

    /// 與 [`remove_pc_from_zone_by_vni`] 相同，但返回 `(是否成功, 訊息文字)`。
    pub async fn remove_pc_from_zone_by_vni_with_msg(
        &self,
        vni: i64,
        pc_uuid: String,
    ) -> ConResult<(bool, String)> {
        let mut client = self.get_client();
        let req = RemovePcFromZoneByVniRequest { vni, pc_uuid };
        let resp = client
            .remove_pc_from_zone_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        Ok((Self::is_ok(&resp), resp.message))
    }
    /// 與 [`update_zone_name_by_vni`] ，但會回傳 `(是否成功, 訊息字串)`。
    pub async fn update_zone_name_by_vni_with_msg(
        &self,
        vni: i64,
        new_name: String,
    ) -> ConResult<(bool, String)> {
        let mut client = self.get_client();
        let req = UpdateZoneNameByVniRequest { vni, new_name };
        let resp = client
            .update_zone_name_by_vni(req)
            .await

            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        let ok = matches!(ResponseType::try_from(resp.r#type), Ok(ResponseType::Ok));
        Ok((ok, resp.message))
    }
}
