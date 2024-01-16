use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    }else if args[0] == "--about" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "about.html";
    }else if args[0] == "--notify" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "notify.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        }else if page == "about.html" {
            inline::get_about()
        }
        else if page == "notify.html" {
            inline::get_notify()
        }
        else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn goto_about(&mut self) {
        goto_about();
    }

    fn goto_notify(&mut self) {
        goto_notify();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn goto_about();
        fn goto_notify();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
