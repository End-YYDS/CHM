use crate::{
    commons::ResponseResult,
    handles::chm::pc_manager::types::{
        DePatchVxlanid, DePutVxlanid, DeletePcGroupRequest, DeletePcRequest, DeletePcResponse,
        GetPcgroupResponseResult, PCManagerRequest as WebPCManagerRequest, PatchPcgroupRequest,
        PcInformation, PostPcgroupRequest, PutPcgroupRequest, RebootPcResponse, ShutdownPcResponse,
        SpecificRequest, Uuid as WebPcSimple, UuidsRequest, Vxlanid,
    },
};
use chm_grpc::restful::{
    AddPcRequest as GrpcAddPcRequest, CreatePcGroupRequest, CreatePcGroupResponse,
    DeletePcGroupResponse, DeletePcsRequest, DeletePcsResponse,
    GetAllPcsResponse as GrpcGetAllPcsResponse, GetPcGroupsResponse, GetSpecificPcsRequest,
    GetSpecificPcsResponse, PatchPcGroupRequest, PatchPcGroupResponse, PcGroup,
    PcSimple as GrpcPcSimple, PutPcGroupRequest, PutPcGroupResponse, RebootPcsRequest,
    RebootPcsResponse, ShutdownPcsRequest, ShutdownPcsResponse,
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
        Self { groupname: value.groupname, cidr: value.cidr }
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

impl From<DePutVxlanid> for PcGroup {
    fn from(value: DePutVxlanid) -> Self {
        Self { groupname: value.groupname, pcs: value.pcs }
    }
}

impl From<PutPcgroupRequest> for PutPcGroupRequest {
    fn from(value: PutPcgroupRequest) -> Self {
        let (k, v) = value.data.into_iter().next().unwrap();
        let vxlanid = k.parse::<i64>().unwrap_or(-1);
        Self { vxlanid, group: Some(v.into()) }
    }
}

impl From<PutPcGroupResponse> for ResponseResult {
    fn from(resp: PutPcGroupResponse) -> Self {
        resp.result.unwrap().into()
    }
}

impl From<PatchPcgroupRequest> for PatchPcGroupRequest {
    fn from(req: PatchPcgroupRequest) -> Self {
        let (vxlanid, data) = req.data.into_iter().next().unwrap();
        match data {
            DePatchVxlanid::Groupname { groupname } => Self {
                vxlanid: vxlanid.parse::<i64>().unwrap_or(-1),
                kind:    Some(chm_grpc::restful::patch_pc_group_request::Kind::Groupname(
                    groupname,
                )),
            },
            DePatchVxlanid::Pcs { pcs } => Self {
                vxlanid: vxlanid.parse::<i64>().unwrap_or(-1),
                kind:    Some(chm_grpc::restful::patch_pc_group_request::Kind::Pcs(
                    chm_grpc::restful::Pcs { pcs },
                )),
            },
        }
    }
}

impl From<PatchPcGroupResponse> for ResponseResult {
    fn from(resp: PatchPcGroupResponse) -> Self {
        resp.result.unwrap().into()
    }
}

impl From<DeletePcGroupRequest> for chm_grpc::restful::DeletePcGroupRequest {
    fn from(value: DeletePcGroupRequest) -> Self {
        Self { vxlanid: value.vxlanid }
    }
}

impl From<DeletePcGroupResponse> for ResponseResult {
    fn from(resp: DeletePcGroupResponse) -> Self {
        resp.result.unwrap().into()
    }
}
