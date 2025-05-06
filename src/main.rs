use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use std::fs;
use anyhow::Result;
use rfd::FileDialog;
use notify_rust::Notification;
use csv;
use rodio::{Decoder, OutputStream, Sink};
use std::io::BufReader;
use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Reader};
use tokio::process::Command;
use chrono::{DateTime, Local};
use std::error::Error;
use winapi::um::iphlpapi;
use winapi::um::iptypes;
use std::mem;
use image;
use egui::IconData;

const MAX_HISTORY_POINTS: usize = 100;
const DEFAULT_PACKET_SIZE: usize = 56;
const MAX_PACKET_SIZE: usize = 65507;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
enum Theme {
    Light,
    Dark,
    System,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::System
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct AlertConfig {
    enabled: bool,
    threshold: f64,
    notify_on_recovery: bool,
    sound_enabled: bool,
    sound_file: Option<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 100.0,
            notify_on_recovery: true,
            sound_enabled: false,
            sound_file: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct IpConfig {
    address: String,
    name: String,
    description: String,
    category: String,
    enabled: bool,
    timeout: u64,
    interface: Option<String>,
    alerts: AlertConfig,
    packet_size: usize,
    track_since: chrono::DateTime<chrono::Local>,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            name: String::new(),
            description: String::new(),
            category: "Other".to_string(),
            enabled: true,
            timeout: 1000,
            interface: None,
            alerts: AlertConfig::default(),
            packet_size: DEFAULT_PACKET_SIZE,
            track_since: chrono::Local::now(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct AppConfig {
    ips: Vec<IpConfig>,
    auto_update: bool,
    update_interval: u64, // in seconds
    show_graphs: bool,
    theme: Theme,
    notifications_enabled: bool,
    geo_db_path: Option<String>,
}

#[derive(Clone)]
struct LatencyHistory {
    timestamps: VecDeque<chrono::DateTime<chrono::Local>>,
    latencies: VecDeque<f64>,
}

#[derive(Clone)]
struct LatencyInfo {
    latency: Option<f64>,
    last_check: chrono::DateTime<chrono::Local>,
    is_active: bool,
    packet_loss: f64,
    history: LatencyHistory,
    min_latency: f64,
    max_latency: f64,
    avg_latency: f64,
    last_alert_state: bool,
    geo_info: Option<GeoInfo>,
    traffic_stats: TrafficStats,
    consecutive_failures: u32,
    consecutive_successes: u32,
}

#[derive(Clone)]
struct GeoInfo {
    country: String,
    city: String,
    latitude: f64,
    longitude: f64,
    isp: String,
}

#[derive(Default, Clone)]
struct TrafficStats {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

struct NetworkInterface {
    name: String,
    description: String,
    traffic_stats: TrafficStats,
}

fn get_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    unsafe {
        let mut buffer_size = 0u32;
        let result = iphlpapi::GetAdaptersInfo(std::ptr::null_mut(), &mut buffer_size);
        if result == winapi::shared::winerror::ERROR_BUFFER_OVERFLOW {
            let mut buffer = vec![0u8; buffer_size as usize];
            let adapter_info = buffer.as_mut_ptr() as *mut iptypes::IP_ADAPTER_INFO;
            if iphlpapi::GetAdaptersInfo(adapter_info, &mut buffer_size) == 0 {
                let mut current = adapter_info;
                while !current.is_null() {
                    let adapter = &*current;
                    let name = std::str::from_utf8(&adapter.AdapterName.iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect::<Vec<u8>>())
                        .unwrap_or("Unknown")
                        .to_string();
                    let description = std::str::from_utf8(&adapter.Description.iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect::<Vec<u8>>())
                        .unwrap_or("Unknown")
                        .to_string();
                    interfaces.push(NetworkInterface {
                        name,
                        description,
                        traffic_stats: TrafficStats::default(),
                    });
                    current = adapter.Next;
                }
            }
        }
    }
    interfaces
}

struct IpLatencyWidget {
    config: AppConfig,
    latency_data: Arc<Mutex<HashMap<String, LatencyInfo>>>,
    new_ip: String,
    new_name: String,
    new_description: String,
    new_category: String,
    runtime: Runtime,
    last_update: chrono::DateTime<chrono::Local>,
    config_path: String,
    show_settings: bool,
    show_diagnostics: bool,
    interfaces: Vec<NetworkInterface>,
    selected_interface: Option<String>,
    geo_reader: Option<Reader<Vec<u8>>>,
    audio_sink: Option<Sink>,
    new_packet_size: usize,
}

impl Default for IpLatencyWidget {
    fn default() -> Self {
        let config_path = "ip_config.json".to_string();
        let config = if let Ok(contents) = fs::read_to_string(&config_path) {
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            AppConfig {
                ips: Vec::new(),
                auto_update: false,
                update_interval: 5,
                show_graphs: true,
                theme: Theme::System,
                notifications_enabled: true,
                geo_db_path: None,
            }
        };

        let interfaces = get_network_interfaces();

        let geo_reader = config.geo_db_path.as_ref().and_then(|path| {
            fs::read(path).ok().map(|data| Reader::from_source(data).unwrap())
        });

        let (_stream, stream_handle) = OutputStream::try_default().unwrap();
        let audio_sink = Sink::try_new(&stream_handle).ok();

        Self {
            config,
            latency_data: Arc::new(Mutex::new(HashMap::new())),
            new_ip: String::new(),
            new_name: String::new(),
            new_description: String::new(),
            new_category: String::new(),
            runtime: Runtime::new().unwrap(),
            last_update: chrono::Local::now(),
            config_path,
            show_settings: false,
            show_diagnostics: false,
            interfaces,
            selected_interface: None,
            geo_reader,
            audio_sink,
            new_packet_size: DEFAULT_PACKET_SIZE,
        }
    }
}

impl IpLatencyWidget {
    async fn check_latency(&self, ip: &str, timeout: u64, interface: Option<&str>, packet_size: usize) -> Option<f64> {
        let mut cmd = Command::new("ping");
        cmd.arg("-n").arg("3");
        cmd.arg("-w").arg(timeout.to_string());
        cmd.arg("-l").arg(packet_size.to_string());
        if let Some(iface) = interface {
            cmd.arg("-S").arg(iface);
        }
        cmd.arg(ip);

        match cmd.output().await {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut successful_pings = 0;
                let mut total_latency = 0.0;
                
                for line in output_str.lines() {
                    if line.contains("time=") {
                        if let Some(time_str) = line.split("time=").nth(1).and_then(|t| t.split("ms").next()) {
                            if let Ok(lat) = time_str.trim().parse::<f64>() {
                                total_latency += lat;
                                successful_pings += 1;
                            }
                        }
                    }
                }

                if successful_pings > 0 {
                    Some(total_latency / successful_pings as f64)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    fn update_geo_info(&self, ip: &str) -> Option<GeoInfo> {
        self.geo_reader.as_ref().and_then(|reader| {
            reader.lookup::<geoip2::City>(ip.parse().ok()?).ok().map(|record| {
                let country = record.country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let city = record.city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let location = record.location.as_ref();
                let latitude = location.and_then(|l| l.latitude).unwrap_or(0.0);
                let longitude = location.and_then(|l| l.longitude).unwrap_or(0.0);

                GeoInfo {
                    country,
                    city,
                    latitude,
                    longitude,
                    isp: "Unknown".to_string(), // We'll need a different database for ISP info
                }
            })
        })
    }

    fn play_alert_sound(&self, sound_file: &str) {
        if let Some(sink) = &self.audio_sink {
            if let Ok(file) = fs::File::open(sound_file) {
                let reader = BufReader::new(file);
                if let Ok(source) = Decoder::new(reader) {
                    sink.append(source);
                }
            }
        }
    }

    fn update_latencies(&mut self) {
        let mut data = self.latency_data.lock().unwrap();
        for ip_config in &self.config.ips {
            if ip_config.enabled {
                let latency = self.runtime.block_on(self.check_latency(
                    &ip_config.address,
                    ip_config.timeout,
                    ip_config.interface.as_deref(),
                    ip_config.packet_size,
                ));
                let now = chrono::Local::now();
                
                let entry = data.entry(ip_config.address.clone()).or_insert_with(|| LatencyInfo {
                    latency: None,
                    last_check: now,
                    is_active: false,
                    packet_loss: 100.0,
                    history: LatencyHistory {
                        timestamps: VecDeque::with_capacity(MAX_HISTORY_POINTS),
                        latencies: VecDeque::with_capacity(MAX_HISTORY_POINTS),
                    },
                    min_latency: f64::MAX,
                    max_latency: 0.0,
                    avg_latency: 0.0,
                    last_alert_state: false,
                    geo_info: self.update_geo_info(&ip_config.address),
                    traffic_stats: TrafficStats::default(),
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                });

                if let Some(lat) = latency {
                    entry.consecutive_successes += 1;
                    entry.consecutive_failures = 0;
                    
                    entry.history.timestamps.push_back(now);
                    entry.history.latencies.push_back(lat);
                    
                    if entry.history.timestamps.len() > MAX_HISTORY_POINTS {
                        entry.history.timestamps.pop_front();
                        entry.history.latencies.pop_front();
                    }

                    entry.min_latency = entry.history.latencies.iter().fold(f64::MAX, |a, &b| a.min(b));
                    entry.max_latency = entry.history.latencies.iter().fold(0.0, |a, &b| a.max(b));
                    entry.avg_latency = entry.history.latencies.iter().sum::<f64>() / entry.history.latencies.len() as f64;

                    // Update traffic stats
                    entry.traffic_stats.packets_sent += 3;
                    entry.traffic_stats.packets_received += 1;
                    entry.traffic_stats.bytes_sent += ip_config.packet_size as u64 * 3;
                    entry.traffic_stats.bytes_received += ip_config.packet_size as u64;
                } else {
                    entry.consecutive_failures += 1;
                    entry.consecutive_successes = 0;
                    entry.traffic_stats.packets_sent += 3;
                    entry.traffic_stats.bytes_sent += ip_config.packet_size as u64 * 3;
                }

                // Update status based on consecutive successes/failures
                let was_active = entry.is_active;
                entry.is_active = entry.consecutive_failures < 2;
                entry.packet_loss = if entry.consecutive_successes > 0 {
                    0.0
                } else {
                    100.0
                };

                entry.latency = latency;
                entry.last_check = now;

                // Check alerts only on status change and after confirmation
                if self.config.notifications_enabled && ip_config.alerts.enabled && was_active != entry.is_active {
                    if !entry.is_active {
                        Notification::new()
                            .summary(&format!("{} is down", ip_config.name))
                            .body(&format!("IP {} is not responding", ip_config.address))
                            .show()
                            .unwrap();

                        if ip_config.alerts.sound_enabled {
                            if let Some(sound_file) = &ip_config.alerts.sound_file {
                                self.play_alert_sound(sound_file);
                            }
                        }
                    } else if ip_config.alerts.notify_on_recovery {
                        Notification::new()
                            .summary(&format!("{} is back up", ip_config.name))
                            .body(&format!("IP {} is now responding", ip_config.address))
                            .show()
                            .unwrap();
                    }
                    entry.last_alert_state = entry.is_active;
                }
            }
        }
        self.last_update = chrono::Local::now();
    }

    fn save_config(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.config)?;
        fs::write(&self.config_path, json)?;
        Ok(())
    }

    fn export_config(&self) -> Result<()> {
        if let Some(path) = FileDialog::new()
            .add_filter("JSON", &["json"])
            .save_file() {
            let json = serde_json::to_string_pretty(&self.config)?;
            fs::write(path, json)?;
        }
        Ok(())
    }

    fn import_config(&mut self) -> Result<()> {
        if let Some(path) = FileDialog::new()
            .add_filter("JSON", &["json"])
            .pick_file() {
            let contents = fs::read_to_string(path)?;
            self.config = serde_json::from_str(&contents)?;
            self.save_config()?;
        }
        Ok(())
    }

    fn remove_ip(&mut self, index: usize) {
        if index < self.config.ips.len() {
            let ip = self.config.ips[index].address.clone();
            self.config.ips.remove(index);
            let mut data = self.latency_data.lock().unwrap();
            data.remove(&ip);
            let _ = self.save_config();
        }
    }

    fn export_statistics(&self) -> Result<(), Box<dyn Error>> {
        let file_path = rfd::FileDialog::new()
            .add_filter("CSV Files", &["csv"])
            .set_directory(std::env::current_dir()?)
            .save_file();

        if let Some(path) = file_path {
            let mut wtr = csv::Writer::from_path(path)?;
            wtr.write_record(&["IP", "Status", "Latency (ms)", "Location", "ISP"])?;
            
            let latency_data = self.latency_data.lock().unwrap();
            for ip_config in &self.config.ips {
                if let Some(info) = latency_data.get(&ip_config.address) {
                    let status = if info.is_active { "Active".to_string() } else { "Inactive".to_string() };
                    let latency = info.latency.map_or("N/A".to_string(), |l| format!("{:.2}", l));
                    let location = info.geo_info.as_ref().map_or("Unknown".to_string(), |g| format!("{}, {}", g.city, g.country));
                    let isp = info.geo_info.as_ref().map_or("Unknown".to_string(), |g| g.isp.clone());
                    
                    wtr.write_record(&[&ip_config.address, &status, &latency, &location, &isp])?;
                }
            }
            wtr.flush()?;
        }
        Ok(())
    }

    fn run_network_diagnostics(&self, ip: &str) -> String {
        let mut diagnostics = String::new();
        
        // Basic reachability
        if let Some(latency) = self.runtime.block_on(self.check_latency(ip, 1000, None, DEFAULT_PACKET_SIZE)) {
            diagnostics.push_str(&format!("IP is reachable (latency: {:.2}ms)\n", latency));
        } else {
            diagnostics.push_str("IP is not reachable\n");
        }

        // Network interface information
        if let Some(iface) = self.interfaces.iter().find(|i| i.name == self.selected_interface.as_deref().unwrap_or("")) {
            diagnostics.push_str(&format!("\nInterface: {}\n", iface.description));
            diagnostics.push_str(&format!("Bytes sent: {}\n", iface.traffic_stats.bytes_sent));
            diagnostics.push_str(&format!("Bytes received: {}\n", iface.traffic_stats.bytes_received));
        }

        // Geolocation information
        if let Some(geo_info) = self.update_geo_info(ip) {
            diagnostics.push_str(&format!("\nLocation: {}, {}\n", geo_info.city, geo_info.country));
            diagnostics.push_str(&format!("ISP: {}\n", geo_info.isp));
            diagnostics.push_str(&format!("Coordinates: {:.4}, {:.4}\n", geo_info.latitude, geo_info.longitude));
        }

        // Network path analysis
        if let Ok(ip_network) = ip.parse::<IpNetwork>() {
            diagnostics.push_str(&format!("\nNetwork: {}\n", ip_network));
        }

        diagnostics
    }

    fn draw_latency_graph(&self, ui: &mut egui::Ui, ip: &str, info: &LatencyInfo) {
        if info.history.latencies.is_empty() {
            return;
        }

        let points: Vec<[f64; 2]> = info.history.timestamps.iter().zip(info.history.latencies.iter())
            .map(|(time, latency)| {
                let timestamp = time.timestamp() as f64;
                [timestamp, *latency]
            })
            .collect();

        Plot::new(format!("latency_plot_{}", ip))
            .height(100.0)
            .show_x(false)
            .include_y(0.0)
            .view_aspect(3.0)
            .show(ui, |plot_ui| {
                plot_ui.line(Line::new(PlotPoints::new(points)).name(ip));
            });
    }
}

// Update the value type to be an enum
enum UpdateValue {
    Bool(bool),
    U64(u64),
}

impl eframe::App for IpLatencyWidget {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme and custom styling
        match self.config.theme {
            Theme::Light => {
                let mut style = (*ctx.style()).clone();
                style.spacing.item_spacing = egui::vec2(10.0, 10.0);
                style.spacing.window_margin = egui::style::Margin::same(10.0);
                style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgba_premultiplied(245, 245, 245, 200);
                style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgba_premultiplied(235, 235, 235, 200);
                style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgba_premultiplied(225, 225, 225, 200);
                style.visuals.widgets.active.bg_fill = egui::Color32::from_rgba_premultiplied(215, 215, 215, 200);
                style.visuals.window_fill = egui::Color32::from_rgba_premultiplied(255, 255, 255, 180);
                style.visuals.panel_fill = egui::Color32::from_rgba_premultiplied(255, 255, 255, 180);
                ctx.set_style(style);
            }
            Theme::Dark => {
                let mut style = (*ctx.style()).clone();
                style.spacing.item_spacing = egui::vec2(10.0, 10.0);
                style.spacing.window_margin = egui::style::Margin::same(10.0);
                style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgba_premultiplied(45, 45, 45, 200);
                style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgba_premultiplied(35, 35, 35, 200);
                style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgba_premultiplied(25, 25, 25, 200);
                style.visuals.widgets.active.bg_fill = egui::Color32::from_rgba_premultiplied(15, 15, 15, 200);
                style.visuals.window_fill = egui::Color32::from_rgba_premultiplied(0, 0, 0, 180);
                style.visuals.panel_fill = egui::Color32::from_rgba_premultiplied(0, 0, 0, 180);
                ctx.set_style(style);
            }
            Theme::System => {
                let mut style = (*ctx.style()).clone();
                style.spacing.item_spacing = egui::vec2(10.0, 10.0);
                style.spacing.window_margin = egui::style::Margin::same(10.0);
                style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgba_premultiplied(45, 45, 45, 200);
                style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgba_premultiplied(35, 35, 35, 200);
                style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgba_premultiplied(25, 25, 25, 200);
                style.visuals.widgets.active.bg_fill = egui::Color32::from_rgba_premultiplied(15, 15, 15, 200);
                style.visuals.window_fill = egui::Color32::from_rgba_premultiplied(0, 0, 0, 180);
                style.visuals.panel_fill = egui::Color32::from_rgba_premultiplied(0, 0, 0, 180);
                ctx.set_style(style);
            }
        }

        // Auto-update logic
        if self.config.auto_update {
            let now = chrono::Local::now();
            let duration = now.signed_duration_since(self.last_update);
            if duration.num_seconds() >= self.config.update_interval as i64 {
                self.update_latencies();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Top bar with title and controls
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("IP Latency Widget").size(24.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(egui::RichText::new("🔍").size(20.0)).clicked() {
                        self.show_diagnostics = !self.show_diagnostics;
                    }
                    if ui.button(egui::RichText::new("⚙").size(20.0)).clicked() {
                        self.show_settings = !self.show_settings;
                    }
                });
            });
            ui.separator();

            // Main content area with scrolling
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.show_settings {
                    self.draw_settings(ui);
                    ui.separator();
                }

                if self.show_diagnostics {
                    self.draw_diagnostics(ui);
                    ui.separator();
                }

                // Add New IP section
                self.draw_add_ip_section(ui);
                ui.separator();

                // IP Status section
                ui.heading(egui::RichText::new("IP Status").size(20.0));
                
                let mut indices_to_remove = Vec::new();
                let mut updates_to_apply = Vec::<(usize, &str, UpdateValue)>::new();
                let mut ips_to_show = Vec::new();
                
                // First pass: Collect all the data we need
                {
                    let latency_data = self.latency_data.lock().unwrap();
                    for (index, ip_config) in self.config.ips.iter().enumerate() {
                        if let Some(info) = latency_data.get(&ip_config.address) {
                            ips_to_show.push((index, ip_config.clone(), info.clone()));
                        }
                    }
                }

                // Second pass: Update UI
                for (index, ip_config, info) in ips_to_show {
                    egui::Frame::none()
                        .inner_margin(egui::style::Margin::same(10.0))
                        .rounding(5.0)
                        .fill(egui::Color32::from_rgba_premultiplied(0, 0, 0, 100))
                        .show(ui, |ui| {
                            self.draw_ip_status(ui, index, &ip_config, &info, &mut updates_to_apply, &mut indices_to_remove);
                        });
                }

                // Apply updates
                for (index, field, value) in updates_to_apply {
                    match field {
                        "enabled" => if let Some(ip_config) = self.config.ips.get_mut(index) {
                            if let UpdateValue::Bool(v) = value {
                                ip_config.enabled = v;
                            }
                        },
                        "timeout" => if let Some(ip_config) = self.config.ips.get_mut(index) {
                            if let UpdateValue::U64(v) = value {
                                ip_config.timeout = v;
                            }
                        },
                        _ => {}
                    }
                }

                // Remove collected indices in reverse order
                for index in indices_to_remove.iter().rev() {
                    self.config.ips.remove(*index);
                }
            });

            // Bottom bar with update button and last update time
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("🔄 Update Latencies").clicked() {
                    self.update_latencies();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("Last update: {}", self.last_update.format("%H:%M:%S")));
                });
            });
        });

        // Request continuous updates
        ctx.request_repaint();
    }
}

impl IpLatencyWidget {
    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .inner_margin(egui::style::Margin::same(10.0))
            .rounding(5.0)
            .fill(egui::Color32::from_rgba_premultiplied(0, 0, 0, 100))
            .show(ui, |ui| {
                ui.collapsing("⚙️ Settings", |ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.config.auto_update, "Auto Update");
                        ui.label("Interval (seconds):");
                        ui.add(egui::DragValue::new(&mut self.config.update_interval)
                            .speed(1)
                            .clamp_range(1..=60));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Theme:");
                        egui::ComboBox::from_label("")
                            .selected_text(match self.config.theme {
                                Theme::Light => "Light",
                                Theme::Dark => "Dark",
                                Theme::System => "System",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.theme, Theme::Light, "Light");
                                ui.selectable_value(&mut self.config.theme, Theme::Dark, "Dark");
                                ui.selectable_value(&mut self.config.theme, Theme::System, "System");
                            });
                    });

                    ui.checkbox(&mut self.config.notifications_enabled, "Enable Notifications");
                    ui.checkbox(&mut self.config.show_graphs, "Show Graphs");

                    ui.horizontal(|ui| {
                        if ui.button("📤 Export Config").clicked() {
                            let _ = self.export_config();
                        }
                        if ui.button("📥 Import Config").clicked() {
                            let _ = self.import_config();
                        }
                    });
                });
            });
    }

    fn draw_diagnostics(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .inner_margin(egui::style::Margin::same(10.0))
            .rounding(5.0)
            .fill(egui::Color32::from_rgba_premultiplied(0, 0, 0, 100))
            .show(ui, |ui| {
                ui.collapsing("🔍 Network Diagnostics", |ui| {
                    for ip_config in &self.config.ips {
                        if ui.button(format!("Diagnose {}", ip_config.name)).clicked() {
                            let diagnostics = self.run_network_diagnostics(&ip_config.address);
                            ui.label(diagnostics);
                        }
                    }
                });
            });
    }

    fn draw_add_ip_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .inner_margin(egui::style::Margin::same(10.0))
            .rounding(5.0)
            .fill(egui::Color32::from_rgba_premultiplied(0, 0, 0, 100))
            .show(ui, |ui| {
                ui.collapsing("➕ Add New IP", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("IP Address:");
                        ui.text_edit_singleline(&mut self.new_ip);
                        ui.label("Name:");
                        ui.text_edit_singleline(&mut self.new_name);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Description:");
                        ui.text_edit_multiline(&mut self.new_description);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Category:");
                        egui::ComboBox::from_label("")
                            .selected_text(&self.new_category)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.new_category, "Server".to_string(), "Server");
                                ui.selectable_value(&mut self.new_category, "Router".to_string(), "Router");
                                ui.selectable_value(&mut self.new_category, "Client".to_string(), "Client");
                                ui.selectable_value(&mut self.new_category, "Other".to_string(), "Other");
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.label("Network Interface:");
                        egui::ComboBox::from_label("")
                            .selected_text(self.selected_interface.as_deref().unwrap_or("Default"))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.selected_interface, None, "Default");
                                for iface in &self.interfaces {
                                    ui.selectable_value(
                                        &mut self.selected_interface,
                                        Some(iface.name.clone()),
                                        &iface.description,
                                    );
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.label("Packet Size (bytes):");
                        ui.add(egui::DragValue::new(&mut self.new_packet_size)
                            .speed(1)
                            .clamp_range(32..=MAX_PACKET_SIZE));
                    });

                    if ui.button("Add IP").clicked() {
                        if !self.new_ip.is_empty() {
                            self.config.ips.push(IpConfig {
                                address: self.new_ip.clone(),
                                name: self.new_name.clone(),
                                description: self.new_description.clone(),
                                category: self.new_category.clone(),
                                enabled: true,
                                timeout: 1000,
                                interface: self.selected_interface.clone(),
                                alerts: AlertConfig {
                                    enabled: true,
                                    threshold: 100.0,
                                    notify_on_recovery: true,
                                    sound_enabled: false,
                                    sound_file: None,
                                },
                                packet_size: self.new_packet_size,
                                track_since: chrono::Local::now(),
                            });
                            self.new_ip.clear();
                            self.new_name.clear();
                            self.new_description.clear();
                            let _ = self.save_config();
                        }
                    }
                });
            });
    }

    fn draw_ip_status(&mut self, ui: &mut egui::Ui, index: usize, ip_config: &IpConfig, info: &LatencyInfo, updates_to_apply: &mut Vec<(usize, &str, UpdateValue)>, indices_to_remove: &mut Vec<usize>) {
        ui.collapsing(format!("{} - {} ({})", ip_config.name, ip_config.address, ip_config.category), |ui| {
            // Description and tracking info
            ui.horizontal(|ui| {
                ui.label(format!("Description: {}", ip_config.description));
            });
            ui.label(format!("Tracking since: {}", ip_config.track_since.format("%Y-%m-%d %H:%M:%S")));
            ui.label(format!("Uptime: {:.1}%", self.calculate_uptime(&ip_config.address)));

            // Status bar
            let status_color = if info.is_active {
                egui::Color32::from_rgb(0, 200, 0)
            } else {
                egui::Color32::from_rgb(200, 0, 0)
            };
            
            ui.horizontal(|ui| {
                ui.colored_label(status_color, &format!(
                    "Status: {} - Latency: {:.2}ms - Packet Loss: {:.1}%",
                    if info.is_active { "Active" } else { "Inactive" },
                    info.latency.unwrap_or(0.0),
                    info.packet_loss
                ));
            });

            // Controls
            ui.horizontal(|ui| {
                let mut enabled = ip_config.enabled;
                ui.checkbox(&mut enabled, "Enabled");
                if enabled != ip_config.enabled {
                    updates_to_apply.push((index, "enabled", UpdateValue::Bool(enabled)));
                }
                
                let mut timeout = ip_config.timeout;
                ui.label("Timeout (ms):");
                ui.add(egui::DragValue::new(&mut timeout)
                    .speed(100)
                    .clamp_range(100..=5000));
                if timeout != ip_config.timeout {
                    updates_to_apply.push((index, "timeout", UpdateValue::U64(timeout)));
                }
            });

            // Statistics
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Min: {:.2}ms - Max: {:.2}ms - Avg: {:.2}ms",
                    info.min_latency,
                    info.max_latency,
                    info.avg_latency
                ));
            });

            // Collapsible sections
            if let Some(geo_info) = &info.geo_info {
                ui.collapsing("🌍 Geolocation", |ui| {
                    ui.label(format!("Location: {}, {}", geo_info.city, geo_info.country));
                    ui.label(format!("ISP: {}", geo_info.isp));
                    ui.label(format!("Coordinates: {:.4}, {:.4}", geo_info.latitude, geo_info.longitude));
                });
            }

            ui.collapsing("📊 Traffic Statistics", |ui| {
                ui.label(format!("Packets sent: {}", info.traffic_stats.packets_sent));
                ui.label(format!("Packets received: {}", info.traffic_stats.packets_received));
                ui.label(format!("Bytes sent: {}", info.traffic_stats.bytes_sent));
                ui.label(format!("Bytes received: {}", info.traffic_stats.bytes_received));
            });

            // Graph
            if self.config.show_graphs && !info.history.latencies.is_empty() {
                ui.collapsing("📈 Latency History", |ui| {
                    self.draw_latency_graph(ui, &ip_config.address, &info);
                });
            }

            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("📊 Export Statistics").clicked() {
                    let _ = self.export_statistics();
                }
                if ui.button("🗑️ Remove").clicked() {
                    indices_to_remove.push(index);
                }
            });
        });
    }

    fn calculate_uptime(&self, ip: &str) -> f64 {
        if let Some(data) = self.latency_data.lock().unwrap().get(ip) {
            let total_checks = data.history.timestamps.len();
            if total_checks == 0 {
                return 0.0;
            }
            let successful_checks = data.history.latencies.iter().filter(|&&lat| lat > 0.0).count();
            (successful_checks as f64 / total_checks as f64) * 100.0
        } else {
            0.0
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_transparent(true)
            .with_decorations(true)
            .with_icon(load_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "IP Latency Widget",
        native_options,
        Box::new(|cc| {
            // Enable transparency
            cc.egui_ctx.set_visuals(egui::Visuals {
                window_fill: egui::Color32::from_rgba_premultiplied(0, 0, 0, 0),
                ..egui::Visuals::dark()
            });
            Box::new(IpLatencyWidget::default())
        }),
    )
}

fn load_icon() -> IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let icon_bytes = include_bytes!("../shourav.ico");
        let image = image::load_from_memory(icon_bytes)
            .expect("Failed to load icon")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
} 