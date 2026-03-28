use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Ebpf; // 修复：替换废弃的 Bpf 为 Ebpf
use bytes::BytesMut;
use mem_cleaner_common::ProcessEvent;

use fxhash::{FxHashMap, FxHashSet};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use smol;
use smol::Async;

// TimerFd 相关依赖
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};

use crossbeam_channel::{bounded, RecvTimeoutError};
use std::collections::VecDeque;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// === 配置常量 ===
const OOM_SCORE_THRESHOLD: i32 = 800;
const INIT_DELAY_SECS: u64 = 2;
const DEFAULT_INTERVAL: u64 = 30;
const MIN_APP_UID: u32 = 10000;

struct ProcInfo {
    start_time: u64,
    cmdline: String,
}

#[repr(C, align(8))]
struct AlignedBpf([u8; include_bytes!("mem_cleaner_ebpf.o").len()]);
static BPF_BYTES: AlignedBpf = AlignedBpf(*include_bytes!("mem_cleaner_ebpf.o"));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WhitelistRule {
    Exact(String),
    Prefix(String),
}

// ====== 扩展配置结构体，增加 enable_log 字段 ======
struct AppConfig {
    interval: u64,
    whitelist: FxHashSet<WhitelistRule>,
    enable_log: bool,
}

// 修复版：基于 timerfd 的异步 sleep（非阻塞 + 安全的 unsafe）
async fn nix_sleep(duration: Duration) -> std::io::Result<()> {
    // 1. 创建非阻塞的 timerfd（必须设置 TFD_NONBLOCK）
    let tfd = TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::TFD_NONBLOCK)
        .map_err(std::io::Error::from)?;

    // 2. 注册到 Smol 的 Async Reactor
    let mut timer = Async::new(tfd)?;

    // 3. 配置定时器（单次触发）
    // 安全证明：此时无异步等待，独占访问底层 TimerFd 不会有数据竞争
    unsafe {
        timer.get_mut().set(
            Expiration::OneShot(TimeSpec::from_duration(duration)),
            TimerSetTimeFlags::empty(),
        )?;
    }

    // 4. 异步等待 timerfd 可读（真正的非阻塞挂起）
    timer.readable().await?;

    // 5. 清理 timerfd 状态（必须调用，否则下次会立即返回）
    // 安全证明：readable() 已完成，无并发 poll，非阻塞模式不会卡线程
    unsafe {
        timer.get_mut().wait()?;
    }

    Ok(())
}

// ================== 辅助函数 (保持逻辑不变，仅适配 Logger 线程安全) ==================
fn get_process_uid(pid: u32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

fn get_oom_score(pid: u32) -> i32 {
    fs::read_to_string(format!("/proc/{}/oom_score_adj", pid))
        .ok()
        .and_then(|c| c.trim().parse::<i32>().ok())
        .unwrap_or(-1000)
}

fn get_start_time(pid: u32) -> Option<u64> {
    let content = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    // 第22个字段是 starttime
    parts.get(21)?.parse::<u64>().ok()
}

fn get_cmdline(pid: u32) -> String {
    fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .and_then(|c| {
            c.split(|&ch| ch == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
        })
        .unwrap_or_default()
}

fn is_in_whitelist(cmdline: &str, whitelist: &FxHashSet<WhitelistRule>) -> bool {
    if whitelist.contains(&WhitelistRule::Exact(cmdline.to_string())) {
        return true;
    }
    whitelist.iter().any(|r| {
        if let WhitelistRule::Prefix(p) = r {
            cmdline.starts_with(p)
        } else {
            false
        }
    })
}

// ====== 扩展 load_config，解析 enable_log: true/false ======
fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = FxHashSet::default();
    let mut enable_log = true; // 默认开启日志

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_wl = false;
        for line in content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if line.starts_with("interval:") {
                if let Some(v) = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()) {
                    interval = v;
                }
                in_wl = false;
            } else if line.starts_with("enable_log:") {
                if let Some(v) = line.split(':').nth(1) {
                    let s = v.trim().to_lowercase();
                    enable_log = matches!(s.as_str(), "true" | "1" | "yes" | "on");
                }
                in_wl = false;
            } else if line.starts_with("whitelist:") {
                in_wl = true;
                if let Some(v) = line.split(':').nth(1) {
                    parse_whitelist_rules(v, &mut whitelist);
                }
            } else if in_wl {
                parse_whitelist_rules(line, &mut whitelist);
            }
        }
    }
    AppConfig {
        interval,
        whitelist,
        enable_log,
    }
}

fn parse_whitelist_rules(line: &str, whitelist: &mut FxHashSet<WhitelistRule>) {
    for pkg in line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some(p) = pkg.strip_suffix(":*") {
            whitelist.insert(WhitelistRule::Prefix(p.to_string()));
        } else {
            whitelist.insert(WhitelistRule::Exact(pkg.to_string()));
        }
    }
}

static TIME_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
fn now_fmt() -> String {
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(TIME_FMT)
        .unwrap_or_default()
}

struct Logger {
    path: std::path::PathBuf,
    last_write_date: Option<Date>,
}
impl Logger {
    fn new(path: Option<String>) -> Option<Self> {
        path.map(|p| Self {
            path: std::path::PathBuf::from(p),
            last_write_date: None,
        })
    }
    fn open_writer(&mut self) -> Option<BufWriter<File>> {
        let today = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .date();
        let mut trunc = false;
        if self.last_write_date != Some(today) {
            if let Ok(m) = fs::metadata(&self.path).and_then(|m| m.modified()) {
                if OffsetDateTime::from(m).date() != today {
                    trunc = true;
                }
            } else {
                trunc = true;
            }
            self.last_write_date = Some(today);
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .append(!trunc)
            .truncate(trunc)
            .open(&self.path)
            .ok()
            .map(BufWriter::new)
    }
    fn write_startup(&mut self) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(
                w,
                "=== 启动时间: {} ===\n⚡ eBPF 进程压制 (Smol+Timerfd) 已启动 ⚡\n",
                now_fmt()
            );
        }
    }
    fn write_cleanup(&mut self, killed_list: &[String]) {
        if let Some(mut w) = self.open_writer() {
            let _ = writeln!(w, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list {
                let _ = writeln!(w, "已清理: {}", pkg);
            }
            let _ = writeln!(w);
        }
    }
}
// 修复：为 Logger 实现 Send（其字段均为 Send，安全）
unsafe impl Send for Logger {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 使用 Smol 启动异步运行时
    smol::block_on(async {
        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            eprintln!("Usage: {} <config_path>[log_path]", args[0]);
            std::process::exit(1);
        }

        let config = Arc::new(load_config(&args[1]));

        // ====== 根据 enable_log 决定是否创建 Logger 实例 ======
        // logger_holder 的类型是 Arc<Mutex<Option<Logger>>>
        let logger_holder: Arc<Mutex<Option<Logger>>> = if config.enable_log {
            Arc::new(Mutex::new(Logger::new(if args.len() > 2 {
                Some(args[2].clone())
            } else {
                None
            })))
        } else {
            // 日志被禁用，保持 None
            Arc::new(Mutex::new(None))
        };

        // 初始化启动日志（仅在 enable_log = true 且 Logger 有路径时写入）
        if config.enable_log {
            if let Ok(mut l) = logger_holder.lock() {
                if let Some(l_inner) = &mut *l {
                    l_inner.write_startup();
                }
            }
        }

        println!("⚡ 初始化 Android 进程压制器 (Smol + Timerfd 稳定版) ⚡");

        println!("📦 加载 eBPF 模块...");
        // 修复：替换废弃的 Bpf::load_bytes 为 Ebpf::load
        let mut bpf = Ebpf::load(&BPF_BYTES.0)?;

        let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_fork")?;
        println!("✅ eBPF 挂载成功: 仅拦截 UID 0 孵化");

        // ==========================================
        // 🧵 业务线程 (纯标准库，无 Smol)
        // ==========================================
        let (tx, rx) = bounded::<u32>(100_000);
        let worker_config = config.clone();
        let worker_logger = logger_holder.clone(); // 传递线程安全的 Logger holder

        thread::spawn(move || {
            let mut monitoring_pids: FxHashMap<u32, ProcInfo> = FxHashMap::default();
            let mut pending_queue: VecDeque<(u32, Instant)> = VecDeque::new();
            let mut next_cleanup = Instant::now() + Duration::from_secs(worker_config.interval);

            println!("🛠️  业务线程已启动，等待 eBPF 投喂...");

            loop {
                let now = Instant::now();
                let mut timeout = next_cleanup.saturating_duration_since(now);

                if let Some(&(_, add_time)) = pending_queue.front() {
                    let mature_time = add_time + Duration::from_secs(INIT_DELAY_SECS);
                    let time_to_mature = mature_time.saturating_duration_since(now);
                    if time_to_mature < timeout {
                        timeout = time_to_mature;
                    }
                }
                if timeout.is_zero() {
                    while let Ok(pid) = rx.try_recv() {
                        pending_queue.push_back((pid, Instant::now()));
                    }
                } else {
                    match rx.recv_timeout(timeout) {
                        Ok(pid) => {
                            pending_queue.push_back((pid, Instant::now()));
                            while let Ok(p) = rx.try_recv() {
                                pending_queue.push_back((p, Instant::now()));
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                let now = Instant::now();
                while let Some(&(pid, add_time)) = pending_queue.front() {
                    if now.duration_since(add_time).as_secs() >= INIT_DELAY_SECS {
                        pending_queue.pop_front();
                        if let Some(uid) = get_process_uid(pid) {
                            if uid >= MIN_APP_UID {
                                let cmdline = get_cmdline(pid);
                                if !cmdline.is_empty()
                                    && cmdline.contains(':')
                                    && !cmdline.contains("zygote")
                                    && !is_in_whitelist(&cmdline, &worker_config.whitelist)
                                {
                                    if let Some(start_time) = get_start_time(pid) {
                                        monitoring_pids.insert(
                                            pid,
                                            ProcInfo {
                                                start_time,
                                                cmdline,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
                if now >= next_cleanup {
                    let mut pids_to_remove = Vec::new();
                    let mut killed_in_this_round = Vec::new();
                    for (&pid, proc) in &monitoring_pids {
                        match get_process_uid(pid) {
                            Some(uid) if uid < MIN_APP_UID => {
                                pids_to_remove.push(pid);
                                continue;
                            }
                            None => {
                                pids_to_remove.push(pid);
                                continue;
                            }
                            _ => {}
                        }
                        match get_start_time(pid) {
                            Some(start) if start != proc.start_time => {
                                pids_to_remove.push(pid);
                                continue;
                            }
                            None => {
                                pids_to_remove.push(pid);
                                continue;
                            }
                            _ => {}
                        }
                        let score = get_oom_score(pid);
                        if score >= OOM_SCORE_THRESHOLD {
                            if kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok() {
                                killed_in_this_round.push(format!(
                                    "PID:{} | OOM:{} | {}",
                                    pid, score, proc.cmdline
                                ));
                                pids_to_remove.push(pid);
                            } else {
                                pids_to_remove.push(pid);
                            }
                        }
                    }
                    // ====== 按 enable_log 决定是否写日志 ======
                    if worker_config.enable_log && !killed_in_this_round.is_empty() {
                        if let Ok(mut l) = worker_logger.lock() {
                            if let Some(l_inner) = &mut *l {
                                l_inner.write_cleanup(&killed_in_this_round);
                            }
                        }
                    }
                    for pid in pids_to_remove {
                        monitoring_pids.remove(&pid);
                    }
                    next_cleanup = Instant::now() + Duration::from_secs(worker_config.interval);
                }
            }
        });

        // ==========================================
        // 🎯 主线程 (Smol I/O 引擎)
        // ==========================================
        let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

        println!("🎧 Smol I/O 引擎已启动，接管所有 CPU 核心中断...");

        // 修复：处理 online_cpus() 的错误类型转换
        let cpus =
            online_cpus().map_err(|(msg, err)| format!("获取CPU列表失败: {}: {}", msg, err))?;
        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)?;
            let tx_clone = tx.clone();

            // 启动 Smol 异步任务，读取每个 CPU 的 perf 事件
            smol::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    // 异步读取 eBPF perf 事件
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for i in 0..events.read {
                                // 修复：添加长度检查，避免内存越界
                                let buf_len = buffers[i].len();
                                let event_size = std::mem::size_of::<ProcessEvent>();
                                if buf_len >= event_size {
                                    let ptr = buffers[i].as_ptr() as *const ProcessEvent;
                                    // 安全读取：已检查长度，无越界风险
                                    let event = unsafe { std::ptr::read_unaligned(ptr) };
                                    let _ = tx_clone.send(event.pid);
                                }
                                // 截断缓冲区，避免重复读取
                                buffers[i].clear();
                            }
                        }
                        Err(_) => continue,
                    }
                }
            })
            .detach(); // 分离任务，让其后台运行
        }

        // 主线程保活循环（非阻塞异步 sleep）
        println!("🚀 系统运行中...");
        loop {
            if let Err(e) = nix_sleep(Duration::from_secs(3600)).await {
                eprintln!("TimerFD error: {:?}, retrying...", e);
                // 异常时降级为短时间阻塞 sleep，避免无限循环
                thread::sleep(Duration::from_secs(5));
            }
        }
    })
}