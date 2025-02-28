use std::{collections::HashMap, sync::RwLock};

use plugin_lib::{
    types::{Provides, Scope},
    Plugin,
};
#[derive(Debug)]
#[allow(unused)]
pub struct PluginEntry {
    pub plugin: Box<dyn Plugin>,
    pub library: libloading::Library,
    pub id: usize,
}
pub(crate) type Plugins = RwLock<HashMap<String, PluginEntry>>;
pub(crate) type Routes = RwLock<HashMap<Scope, Provides>>;
pub(crate) type PluginCreate = unsafe fn() -> *mut dyn Plugin;
