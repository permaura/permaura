//! Children that must not outlive the gateway: the tunnel connector, a command connector's program, a notification CLI.
//!
//! On Linux every child started here carries `PR_SET_PDEATHSIG` set to `SIGKILL`, so the kernel kills it the moment the gateway ends, whatever ends it: a plain child survives its parent's SIGKILL, reparented to init, and on the first crash test the tunnel connector kept answering on the public hostname for a gateway that was already dead. The signal reaches only the program started here, not anything it starts itself, and not a set-user-ID or file-capability program.
//!
//! The kernel ties that signal to the thread that forked the child, not to the process, so on Linux every child is forked on one dedicated thread that runs for the life of the process. Forked on a Tokio worker, the connector was killed whenever the runtime retired that worker: `block_in_place`, which the gateway's store calls on ordinary paths, hands the worker's core to a replacement, and the original thread exits once the blocking pool's keep-alive lapses. Off Linux there is no such signal, so a child is started in place, except a standard child an async caller starts, which goes through the same thread so the start never blocks the runtime; the gateway stops the connector on its way out, and a Tokio child's own `kill_on_drop` and timeout still apply everywhere.

use std::io;
use std::process::{Child, Command};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

/// The name of the thread every child started here is forked on, on Linux; elsewhere only a standard child an async caller starts ([`spawn_std_dying_with_this_process`]) is, and any other child is started on the caller's thread.
pub const SPAWNER_THREAD: &str = "permaura-child-spawner";

/// How long a Tokio caller waits for the spawner. A start takes milliseconds; one unanswered for this long is stuck in an exec, and every start queues behind it, so the caller is refused rather than held.
pub const SPAWN_WITHIN: Duration = Duration::from_secs(10);

type Job = Box<dyn FnOnce() + Send>;

/// The spawner thread's queue, started on first use. Held here for the life of the process, so the thread's loop never ends while the process runs.
static SPAWNER: Mutex<Option<mpsc::SyncSender<Job>>> = Mutex::new(None);

/// Start `cmd` so that, on Linux, it dies when this process ends and at no other time. Off Linux there is no signal to arm, so it is started in place.
pub fn spawn_dying_with_this_process(mut cmd: Command) -> io::Result<Child> {
    #[cfg(target_os = "linux")]
    {
        arm_parent_death_signal(&mut cmd);
        on_spawner_thread(move || cmd.spawn())?
    }
    #[cfg(not(target_os = "linux"))]
    cmd.spawn()
}

/// [`spawn_dying_with_this_process`] for a Tokio command, which its caller awaits, times out and keeps `kill_on_drop` on. Called from inside a Tokio runtime, whose driver the child is registered with. On Linux the wait for the spawner is awaited, never blocked on, and refused after [`SPAWN_WITHIN`]; off Linux it is started in place.
///
/// The signal reaches only the program started here: Linux clears it in that program's own children, and on an exec of a set-user-ID or file-capability binary. A caller that must end those too puts the program in a process group of its own and kills the group ([`kill_process_group`]).
pub async fn spawn_tokio_dying_with_this_process(cmd: tokio::process::Command) -> io::Result<tokio::process::Child> {
    #[cfg(target_os = "linux")]
    {
        spawn_tokio_on_spawner(cmd, SPAWN_WITHIN).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        caller_runtime()?;
        let mut cmd = cmd;
        cmd.spawn()
    }
}

/// Start a standard child without blocking an async runtime, skipping canceled queued starts.
pub async fn spawn_std_dying_with_this_process(mut cmd: Command) -> io::Result<Child> {
    #[cfg(target_os = "linux")]
    arm_parent_death_signal(&mut cmd);
    let (answer, answered) = tokio::sync::oneshot::channel();
    let queued = std::time::Instant::now();
    queue(Box::new(move || {
        if answer.is_closed() || queued.elapsed() >= SPAWN_WITHIN { return; }
        if let Err(Ok(mut child)) = answer.send(cmd.spawn()) {
            #[cfg(target_os = "linux")]
            kill_process_group(child.id());
            let _ = child.kill();
            let _ = child.wait();
        }
    }))?;
    match tokio::time::timeout(SPAWN_WITHIN, answered).await {
        Ok(Ok(spawned)) => spawned,
        Ok(Err(_)) => Err(io::Error::other("the thread that starts child processes did not answer")),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "the child process spawner did not answer before its deadline")),
    }
}

/// The runtime the caller runs in, which a Tokio child is registered with; refused outside one rather than panicking in Tokio.
fn caller_runtime() -> io::Result<tokio::runtime::Handle> {
    tokio::runtime::Handle::try_current()
        .map_err(|e| io::Error::other(format!("a Tokio child process is started from inside a Tokio runtime: {e}")))
}

/// End every process in the group `leader` leads, the program a caller started with `process_group(0)` and whatever it started itself. Linux only, where command connectors are put in a group of their own; elsewhere they stay in the gateway's group, where a service manager's cleanup works through it.
#[cfg(target_os = "linux")]
pub fn kill_process_group(leader: u32) {
    let Ok(group) = libc::pid_t::try_from(leader) else { return };
    if group <= 1 {
        return;
    }
    // SAFETY: kill only sends a signal; a negative pid names the process group `group`, which the caller made for this one program.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn spawn_tokio_on_spawner(mut cmd: tokio::process::Command, within: Duration) -> io::Result<tokio::process::Child> {
    let runtime = caller_runtime()?;
    #[cfg(target_os = "linux")]
    arm_parent_death_signal(cmd.as_std_mut());
    let (answer, answered) = tokio::sync::oneshot::channel();
    let queued = std::time::Instant::now();
    queue(Box::new(move || {
        if answer.is_closed() || queued.elapsed() >= within { return; }
        let _entered = runtime.enter();
        // A caller that gave up on a stuck spawner is no longer there to watch the child, so it is killed rather than left running.
        if let Err(Ok(mut child)) = answer.send(cmd.spawn()) {
            #[cfg(target_os = "linux")]
            if let Some(pid) = child.id() { kill_process_group(pid); }
            let _ = child.start_kill();
        }
    }))?;
    match tokio::time::timeout(within, answered).await {
        Ok(Ok(spawned)) => spawned,
        Ok(Err(_)) => Err(io::Error::other("the thread that starts child processes did not answer")),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the thread that starts child processes has not answered in {} seconds: an earlier start is stuck in its exec", within.as_secs_f32()),
        )),
    }
}

#[cfg(target_os = "linux")]
fn arm_parent_death_signal(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: prctl and getppid only read or set this child's own process attributes and touch no memory; both are async-signal-safe, and the closure runs in the child between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            // A gateway that died between the fork and the prctl has already handed this child to another parent, so the signal would never come.
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}

/// Run `f` on the spawner thread and hand back what it returned. A job already on the spawner runs `f` there and then, since waiting on the queue would wait for itself.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn on_spawner_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> io::Result<T> {
    if std::thread::current().name() == Some(SPAWNER_THREAD) {
        return Ok(f());
    }
    let (answer, answered) = mpsc::sync_channel(1);
    queue(Box::new(move || {
        let _ = answer.send(f());
    }))?;
    answered
        .recv()
        .map_err(|_| io::Error::other("the thread that starts child processes did not answer"))
}

fn queue(job: Job) -> io::Result<()> {
    let mut spawner = SPAWNER.lock().unwrap_or_else(|p| p.into_inner());
    let queue = match spawner.as_ref() {
        Some(queue) => queue.clone(),
        None => spawner.insert(start()?).clone(),
    };
    match queue.try_send(job) {
        Ok(()) => Ok(()),
        Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(io::ErrorKind::WouldBlock, "the child process queue is full; retry after its earlier starts finish")),
        Err(mpsc::TrySendError::Disconnected(_)) => {
            *spawner = None;
            Err(io::Error::other("the thread that starts child processes has ended"))
        }
    }
}

fn start() -> io::Result<mpsc::SyncSender<Job>> {
    let (queue, jobs) = mpsc::sync_channel::<Job>(64);
    std::thread::Builder::new().name(SPAWNER_THREAD.into()).spawn(move || {
        unblock_every_signal();
        for job in jobs {
            // A job that panics must not end this thread: every child it forked would die with it.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        }
    })?;
    Ok(queue)
}

/// A child inherits the forking thread's signal mask, and this thread would otherwise take whatever mask the thread that first used it had.
fn unblock_every_signal() {
    #[cfg(unix)]
    // SAFETY: a zeroed sigset is valid storage for sigemptyset to initialize, and the call changes only this thread's mask.
    unsafe {
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        libc::pthread_sigmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A runtime shaped like a small VPS's: one worker, and a keep-alive short enough that a retired worker exits within the test.
    fn one_worker_runtime(stopped: mpsc::Sender<std::thread::ThreadId>) -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_keep_alive(Duration::from_millis(100))
            .enable_all()
            .on_thread_stop(move || {
                let _ = stopped.send(std::thread::current().id());
            })
            .build()
            .unwrap()
    }

    /// What the gateway store's `blocking_section` and `lock_donating` do on the worker that started the child.
    fn donate_this_workers_core() {
        tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(200)));
    }

    fn sleeper(secs: &str) -> Command {
        let mut cmd = Command::new("sleep");
        cmd.arg(secs);
        cmd
    }

    fn tokio_sleeper(secs: &str) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg(secs).kill_on_drop(true);
        cmd
    }

    #[test]
    fn a_full_child_queue_refuses_more_work_without_waiting() {
        let queue = start().unwrap();
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        queue.send(Box::new(move || { entered.send(()).unwrap(); released.recv().unwrap(); })).unwrap();
        ready.recv().unwrap();
        for _ in 0..64 { assert!(queue.try_send(Box::new(|| {})).is_ok()); }
        let overflow = queue.try_send(Box::new(|| {}));
        release.send(()).unwrap();
        assert!(matches!(overflow, Err(mpsc::TrySendError::Full(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_standard_child_start_leaves_the_async_runtime_free() {
        const MODE: &str = "PERMAURA_TEST_STD_SPAWNER";
        if std::env::var_os(MODE).is_none() {
            let output = Command::new(std::env::current_exe().unwrap()).args(["--exact", "child::tests::a_standard_child_start_leaves_the_async_runtime_free", "--nocapture"]).env(MODE, "1").output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        let (entered, ready) = mpsc::channel();
        let busy = std::thread::spawn(move || on_spawner_thread(move || { entered.send(()).unwrap(); std::thread::sleep(Duration::from_millis(300)); }).unwrap());
        ready.recv().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let started = std::time::Instant::now();
        let refused = rt.block_on(async { tokio::time::timeout(Duration::from_millis(40), spawn_std_dying_with_this_process(sleeper("0"))).await });
        let elapsed = started.elapsed();
        busy.join().unwrap();
        assert!(refused.is_err(), "the queued start was canceled");
        assert!(elapsed < Duration::from_millis(200), "a standard start held the runtime for {elapsed:?}");
    }

    /// Runs on every platform: a job handed to the spawner runs on it, not on the worker that asked, and it is still the one running jobs after the runtime retired that worker. On Linux every child is forked there; elsewhere only a standard child an async caller starts ([`spawn_std_dying_with_this_process`]).
    #[test]
    fn a_child_is_forked_on_a_thread_that_outlives_the_worker_that_asked_for_it() {
        let (stopped_tx, stopped) = mpsc::channel();
        let rt = one_worker_runtime(stopped_tx);
        let (worker, forker, name) = rt.block_on(async {
            tokio::spawn(async {
                let worker = std::thread::current().id();
                let (forker, name) = on_spawner_thread(|| (std::thread::current().id(), std::thread::current().name().map(str::to_string))).unwrap();
                donate_this_workers_core();
                (worker, forker, name)
            })
            .await
            .unwrap()
        });
        assert_ne!(forker, worker, "the child is not forked on the Tokio worker");
        assert_eq!(name.as_deref(), Some(SPAWNER_THREAD));
        let retired = stopped.recv_timeout(Duration::from_secs(3)).expect("the runtime retired a worker");
        assert_eq!(retired, worker, "the worker that asked for the child retired while the runtime lives on");
        assert_eq!(rt.block_on(async { tokio::spawn(async { 7 }).await.unwrap() }), 7, "the runtime is still serving");
        let again = on_spawner_thread(|| std::thread::current().id()).unwrap();
        assert_eq!(again, forker, "the thread the child was forked on is still there after the worker that asked for it has gone");
    }

    /// A job that itself asks the spawner for something runs it there and then, rather than waiting on a queue only it could drain.
    #[test]
    fn a_job_that_asks_the_spawner_again_does_not_deadlock_it() {
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let inner = on_spawner_thread(|| on_spawner_thread(|| 7).ok()).ok().flatten();
            let _ = done.send(inner);
        });
        assert_eq!(finished.recv_timeout(Duration::from_secs(3)).expect("the spawner answered rather than deadlocking"), Some(7));
        assert_eq!(on_spawner_thread(|| 8).unwrap(), 8, "and it still serves");
    }

    /// The spawner forks with no signal blocked, whatever the thread that first used it had blocked, since a child inherits the forking thread's mask.
    #[cfg(unix)]
    #[test]
    fn the_spawner_forks_with_no_signal_blocked() {
        let blocked = std::thread::spawn(|| {
            // SAFETY: a zeroed sigset is valid storage for sigemptyset to initialize; only this thread's mask changes.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR1);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            }
            on_spawner_thread(|| {
                // SAFETY: as above; a null new set only reads this thread's mask.
                unsafe {
                    let mut current: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut current);
                    libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current);
                    libc::sigismember(&current, libc::SIGUSR1) == 1
                }
            })
            .unwrap()
        })
        .join()
        .unwrap();
        assert!(!blocked, "the spawner has SIGUSR1 blocked, so its children would too");
    }

    /// A stuck spawner refuses a Tokio caller after the bound without blocking its runtime, and a child started after the caller gave up is killed rather than left unwatched.
    #[cfg(unix)]
    #[test]
    fn a_stuck_spawner_refuses_a_tokio_caller_without_blocking_its_runtime() {
        let marker = std::env::temp_dir().join(format!("permaura-spawner-late-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let busy = std::thread::spawn(|| on_spawner_thread(|| std::thread::sleep(Duration::from_secs(2))).unwrap());
        std::thread::sleep(Duration::from_millis(100));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (spawned, timer_fired, refused) = rt.block_on(async {
            let started = std::time::Instant::now();
            let mut cmd = tokio::process::Command::new("sh");
            cmd.args(["-c", "exit 0"]);
            use std::os::unix::process::CommandExt as _;
            let marker_path = std::ffi::CString::new(marker.to_string_lossy().as_bytes()).unwrap();
            // SAFETY: open and close are async-signal-safe and the path remains owned by the closure.
            unsafe { cmd.as_std_mut().pre_exec(move || {
                let fd = libc::open(marker_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600);
                if fd >= 0 { libc::close(fd); }
                Ok(())
            }); }

            let timer = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                started.elapsed()
            };
            let spawn = async {
                let spawned = spawn_tokio_on_spawner(cmd, Duration::from_millis(400)).await;
                (spawned, started.elapsed())
            };
            let (fired, (spawned, refused)) = tokio::join!(timer, spawn);
            (spawned, fired, refused)
        });
        busy.join().unwrap();
        assert_eq!(spawned.err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
        assert!(timer_fired < Duration::from_millis(300), "the runtime was held while the spawner was busy: {timer_fired:?}");
        assert!(refused < Duration::from_millis(1500), "{refused:?}");
        std::thread::sleep(Duration::from_secs(3));
        assert!(!marker.exists(), "the child started after its caller gave up ran unwatched");
    }

    #[test]
    fn a_panicking_job_does_not_end_the_spawner() {
        let before = on_spawner_thread(|| std::thread::current().id()).unwrap();
        assert!(on_spawner_thread::<()>(|| panic!("a job that panics")).is_err());
        assert_eq!(on_spawner_thread(|| std::thread::current().id()).unwrap(), before);
    }

    /// A Tokio child started here is still the runtime's: it is awaited, killed on drop, and refused outside a runtime rather than registered with none.
    #[cfg(unix)]
    #[test]
    fn a_tokio_child_stays_awaitable_and_killed_on_drop() {
        let mut outside = std::pin::pin!(spawn_tokio_dying_with_this_process(tokio_sleeper("1")));
        let polled = std::future::Future::poll(outside.as_mut(), &mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(matches!(polled, std::task::Poll::Ready(Err(_))), "no runtime, no child");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let mut quick = tokio::process::Command::new("true");
            quick.kill_on_drop(true);
            let status = spawn_tokio_dying_with_this_process(quick).await.unwrap().wait().await.unwrap();
            assert!(status.success());
            let dropped = spawn_tokio_dying_with_this_process(tokio_sleeper("30")).await.unwrap();
            let pid = dropped.id().unwrap() as i32;
            drop(dropped);
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while alive(pid) && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(!alive(pid), "kill_on_drop still holds");
        });
    }

    #[cfg(unix)]
    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only asks whether the process exists; nothing is delivered.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        // A killed child nobody has reaped yet is a zombie, which is gone for this purpose: one reparented inside a container with no reaping init, or one this test's own runtime has not collected.
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit_once(')').and_then(|(_, rest)| rest.trim_start().chars().next()))
            .or_else(|| {
                Command::new("ps")
                    .args(["-o", "stat=", "-p", &pid.to_string()])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .and_then(|s| s.trim().chars().next())
            });
        state != Some('Z')
    }

    /// The half of this check that runs everywhere: children started from a worker that then donates its core, std and Tokio alike, are still running after that worker retired. On Linux this is the regression: forked on the worker, they were SIGKILLed when the worker exited.
    #[cfg(unix)]
    #[test]
    fn children_started_from_a_worker_survive_that_worker_retiring() {
        let (stopped_tx, stopped) = mpsc::channel();
        let rt = one_worker_runtime(stopped_tx);
        let (worker, mut child, tokio_pid) = rt.block_on(async {
            tokio::spawn(async {
                let child = spawn_dying_with_this_process(sleeper("30")).expect("sleep starts");
                let tokio_child = spawn_tokio_dying_with_this_process(tokio_sleeper("30")).await.expect("sleep starts");
                donate_this_workers_core();
                let tokio_pid = tokio_child.id().unwrap() as i32;
                // Left running past this task: dropping it would kill it.
                std::mem::forget(tokio_child);
                (std::thread::current().id(), child, tokio_pid)
            })
            .await
            .unwrap()
        });
        let retired = stopped.recv_timeout(Duration::from_secs(3)).expect("the runtime retired a worker");
        assert_eq!(retired, worker);
        std::thread::sleep(Duration::from_millis(500));
        let status = child.try_wait().unwrap();
        let tokio_alive = alive(tokio_pid);
        let _ = child.kill();
        let _ = child.wait();
        // SAFETY: a pid this test started a moment ago; SIGKILL only ends that process.
        unsafe { libc::kill(tokio_pid, libc::SIGKILL) };
        assert!(status.is_none(), "the std child died with the worker that asked for it: {status:?}");
        assert!(tokio_alive, "the Tokio child died with the worker that asked for it");
    }

    const FAKE_GATEWAY: &str = "PERMAURA_CHILD_TEST_FAKE_GATEWAY";

    /// Not a test on its own: run by [`children_die_when_the_gateway_process_ends`] as a stand-in gateway. It starts a std and a Tokio child from a worker, retires that worker, prints both pids and waits to be killed.
    #[test]
    fn fake_gateway_for_the_parent_death_test() {
        if std::env::var_os(FAKE_GATEWAY).is_none() {
            return;
        }
        let (stopped_tx, stopped) = mpsc::channel();
        let rt = one_worker_runtime(stopped_tx);
        let pids = rt.block_on(async {
            tokio::spawn(async {
                let child = spawn_dying_with_this_process(sleeper("60")).expect("sleep starts");
                let tokio_child = spawn_tokio_dying_with_this_process(tokio_sleeper("60")).await.expect("sleep starts");
                donate_this_workers_core();
                let pids = (child.id(), tokio_child.id().unwrap());
                std::mem::forget(tokio_child);
                pids
            })
            .await
            .unwrap()
        });
        let _ = stopped.recv_timeout(Duration::from_secs(3));
        println!("child-pids {} {}", pids.0, pids.1);
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(60));
    }

    /// The Linux half of the check above: both children outlive the retired worker and die when the process that started them is killed. Ignored on other Unix systems, where no parent-death signal exists, and compiled on every Unix so it cannot rot.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "the parent-death signal is Linux only")]
    fn children_die_when_the_gateway_process_ends() {
        use std::io::BufRead as _;
        let mut gateway = Command::new(std::env::current_exe().unwrap())
            .args(["child::tests::fake_gateway_for_the_parent_death_test", "--exact", "--nocapture", "--test-threads=1"])
            .env(FAKE_GATEWAY, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the stand-in gateway starts");
        let mut lines = std::io::BufReader::new(gateway.stdout.take().unwrap()).lines();
        // The harness prints the test's name on the same line before the test runs, so the marker is looked for anywhere in it.
        let pids: Vec<i32> = lines
            .by_ref()
            .map_while(Result::ok)
            .find_map(|line| line.rsplit_once("child-pids ").map(|(_, p)| p.split_whitespace().filter_map(|n| n.parse().ok()).collect()))
            .expect("the stand-in gateway names its children");
        assert_eq!(pids.len(), 2, "{pids:?}");
        std::thread::sleep(Duration::from_millis(500));
        let survived_the_worker: Vec<bool> = pids.iter().map(|&pid| alive(pid)).collect();
        let _ = gateway.kill();
        let _ = gateway.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while pids.iter().any(|&pid| alive(pid)) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let outlived: Vec<i32> = pids.iter().copied().filter(|&pid| alive(pid)).collect();
        for &pid in &outlived {
            // SAFETY: a pid this test read from its own stand-in gateway, which started it; SIGKILL only ends that process.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert_eq!(survived_the_worker, vec![true, true], "a child died when the worker that started it retired");
        assert!(outlived.is_empty(), "these children outlived the gateway that started them: {outlived:?}");
    }
}
