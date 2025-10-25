use crate::{
    commons::ResponseResult,
    handles::chm::pc_manager::types::{
        DeletePcRequest, DeletePcResponse, GetPcgroupResponseResult,
        PCManagerRequest as WebPCManagerRequest, PcInformation, PostPcgroupRequest,
        RebootPcResponse, ShutdownPcResponse, SpecificRequest, Uuid as WebPcSimple, UuidsRequest,
        Vxlanid,
    },
};
use chm_grpc::restful::{
    AddPcRequest as GrpcAddPcRequest, CreatePcGroupRequest, CreatePcGroupResponse,
    DeletePcsRequest, DeletePcsResponse, GetAllPcsResponse as GrpcGetAllPcsResponse,
    GetPcGroupsResponse, GetSpecificPcsRequest, GetSpecificPcsResponse, PcGroup,
    PcSimple as GrpcPcSimple, RebootPcsRequest, RebootPcsResponse, ShutdownPcsRequest,
    ShutdownPcsResponse,
};
use std::collections::HashMap;

impl From<WebPCManagerRequest> for GrpcAddPcRequest {
    fn from(item: WebPCManagerRequest) -> Self {
        GrpcAddPcRequest { ip: item.ip, password: item.password }
    }
}

impl From<GrpcPcSimple> for WebPcSimple {
    fn from(item: GrpcPcSimple) -> Self {
        Self { hostname: item.hostname, ip: item.ip, status: item.status }
    }
}

impl From<GrpcGetAllPcsResponse> for PcInformation {
    fn from(resp: GrpcGetAllPcsResponse) -> Self {
        let pcs = resp.pcs.into_iter().map(|(k, v)| (k, v.into())).collect();
        Self { pcs, length: resp.length as usize }
    }
}

impl From<SpecificRequest> for GetSpecificPcsRequest {
    fn from(value: SpecificRequest) -> Self {
        Self { uuid: value.uuid }
    }
}

impl From<GetSpecificPcsResponse> for PcInformation {
    fn from(resp: GetSpecificPcsResponse) -> Self {
        let pcs = resp.pcs.into_iter().map(|(k, v)| (k, v.into())).collect();
        Self { pcs, length: resp.length as usize }
    }
}

impl From<DeletePcRequest> for DeletePcsRequest {
    fn from(value: DeletePcRequest) -> Self {
        Self { uuids: value.uuids, passwords: value.passwords }
    }
}

impl From<DeletePcsResponse> for DeletePcResponse {
    fn from(resp: DeletePcsResponse) -> Self {
        let uuids: HashMap<String, ResponseResult> =
            resp.results.into_iter().map(|(k, v)| (k, v.into())).collect();
        let length = uuids.len();
        Self { pcs: uuids, length }
    }
}

impl From<UuidsRequest> for RebootPcsRequest {
    fn from(value: UuidsRequest) -> Self {
        Self { uuids: value.uuids }
    }
}

impl From<UuidsRequest> for ShutdownPcsRequest {
    fn from(value: UuidsRequest) -> Self {
        Self { uuids: value.uuids }
    }
}

impl From<RebootPcsResponse> for RebootPcResponse {
    fn from(resp: RebootPcsResponse) -> Self {
        let uuids: HashMap<String, ResponseResult> =
            resp.results.into_iter().map(|(k, v)| (k, v.into())).collect();
        let length = uuids.len();
        Self { pcs: uuids, length }
    }
}

impl From<ShutdownPcsResponse> for ShutdownPcResponse {
    fn from(resp: ShutdownPcsResponse) -> Self {
        let uuids: HashMap<String, ResponseResult> =
            resp.results.into_iter().map(|(k, v)| (k, v.into())).collect();
        let length = uuids.len();
        Self { pcs: uuids, length }
    }
}

impl From<PostPcgroupRequest> for CreatePcGroupRequest {
    fn from(value: PostPcgroupRequest) -> Self {
        Self { groupname: value.groupname, describe: value.describe }
    }
}
impl From<CreatePcGroupResponse> for ResponseResult {
    fn from(resp: CreatePcGroupResponse) -> Self {
        resp.result.unwrap().into()
    }
}

impl From<PcGroup> for Vxlanid {
    fn from(group: PcGroup) -> Self {
        Self { groupname: group.groupname, pcs: group.pcs }
    }
}

impl From<GetPcGroupsResponse> for GetPcgroupResponseResult {
    fn from(resp: GetPcGroupsResponse) -> Self {
        let groups: HashMap<String, Vxlanid> =
            resp.groups.into_iter().map(|(k, v)| (k.to_string(), v.into())).collect();
        let length = groups.len();
        Self { groups, length }
    }
}
