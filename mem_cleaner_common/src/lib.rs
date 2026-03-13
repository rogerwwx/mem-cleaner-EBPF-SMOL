#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub pid: u32,
    // 我们只需要 PID，UID 在用户态查更准（因为 Fork 瞬间 UID 还没变）
    pub _padding: u32,
}
