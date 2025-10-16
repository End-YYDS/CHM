use crate::handles::chm::user::types::UserEntry;

impl From<chm_grpc::restful::UserEntry> for UserEntry {
    fn from(item: chm_grpc::restful::UserEntry) -> Self {
        UserEntry {
            username:       item.username,
            group:          item.group,
            home_directory: item.home_directory,
            shell:          item.shell,
        }
    }
}
