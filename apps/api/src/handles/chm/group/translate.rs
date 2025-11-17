use crate::handles::chm::group::types::GroupEntry;

impl From<chm_grpc::restful::GroupInfo> for GroupEntry {
    fn from(item: chm_grpc::restful::GroupInfo) -> Self {
        GroupEntry { groupname: item.groupname, users: item.users }
    }
}
