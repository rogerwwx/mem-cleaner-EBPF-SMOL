#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use mem_cleaner_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // 1. 获取触发 Fork 的父进程 UID
    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

    // 2. 终极过滤：只允许 Root (UID 0) 触发的事件通过！
    // Zygote 孵化 App 时，身份是 UID 0。
    // App 运行后自己创建几百个下载线程时，身份是 10xxx，直接在内核被无情抛弃，零开销！
    if uid == 0 {
        // 读取 Linux 64位 sched_process_fork 结构体中的 child_pid (偏移量44)
        let child_pid_offset = 44;
        let child_pid: u32 = unsafe {
            match ctx.read_at(child_pid_offset) {
                Ok(val) => val,
                Err(_) => return 0,
            }
        };

        // 3. 将极其纯净的 PID 发给用户态
        let event = ProcessEvent {
            pid: child_pid,
            _padding: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
