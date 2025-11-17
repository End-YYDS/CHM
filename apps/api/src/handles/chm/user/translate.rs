use crate::handles::chm::user::types::GetUserEntry;

impl From<chm_grpc::restful::UserEntry> for GetUserEntry {
    fn from(item: chm_grpc::restful::UserEntry) -> Self {
        GetUserEntry {
            username:       item.username,
            cn:             item.cn,
            sn:             item.sn,
            home_directory: item.home_directory,
            shell:          item.shell,
            given_name:     item.given_name,
            display_name:   item.display_name,
            gid_number:     item.gid_number,
            group:          item.group,
            gecos:          item.gecos,
        }
    }
}
