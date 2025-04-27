"""
Think uberhard. Modify the following class so that they can receive a particular message from the control thread to let workers pause, resume, etc. Build a new type of construct/class/etc that allows the tasks as they are iterating over an iterable to check to see if there's a pending message that requires them to pause, return immediately, etc. this check should be completely transparent and be handled separately from the business task function logic.
"""

import contextlib
import logging
import multiprocessing
import multiprocessing.shared_memory
import os
import time

logger = logging.getLogger(__name__)


class ListenerContext:
    """
    Context manager for multiprocessing.connection.Listener.
    Ensures the listener is closed on exit.
    """

    def __init__(self, pipe_name, authkey):
        self.pipe_name = pipe_name
        self.authkey = authkey
        self.listener = None

    def __enter__(self):
        self.listener = multiprocessing.connection.Listener(
            self.pipe_name, authkey=self.authkey
        )
        logger.info("Listener created.")
        return self.listener

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.listener is not None:
            try:
                logger.info("Closing listener.")
                self.listener.close()
            except Exception as e:
                logger.error(f"Error closing listener: {e}")


class TaskSignalState:
    """Signal mechanism for controlling worker tasks across processes."""

    # Shared memory format: [paused(1B), stopped(1B), log_level(4B)]

    def __init__(self, shared_mem_name):
        self.shared_mem_name = shared_mem_name
        self.shm = multiprocessing.shared_memory.SharedMemory(name=shared_mem_name)

    def close(self):
        """Close the shared memory."""
        if hasattr(self, "shm") and self.shm:
            self.shm.close()

    def is_paused(self):
        """Check if tasks should be paused."""
        return bool(self.shm.buf[0])

    def is_stopped(self):
        """Check if tasks should be stopped."""
        return bool(self.shm.buf[1])

    def get_log_level(self):
        """Get the current log level."""
        return int.from_bytes(self.shm.buf[2:6], byteorder="little")

    def check_control(self):
        """
        Check control signals and handle pause/stop.
        Returns True if execution should continue, False if it should stop.
        """
        # Check for stop signal
        if self.is_stopped():
            return False

        # Check for pause signal
        if self.is_paused():
            # Wait until unpaused or stopped
            while self.is_paused() and not self.is_stopped():
                time.sleep(0.1)  # Avoid busy waiting

            # Check if stopped while paused
            if self.is_stopped():
                return False

        return True  # Continue execution


class TaskSignalManager:
    """Manager class for controlling task execution across processes."""

    def __init__(self):
        # Create shared memory for control signals
        # Format: [paused(1B), stopped(1B), log_level(4B)]
        self.shared_mem_name = f"task_signal_{os.getpid()}_{time.time_ns()}"
        self.shm = multiprocessing.shared_memory.SharedMemory(
            name=self.shared_mem_name, create=True, size=6
        )

        # Initialize to not paused, not stopped, default log level
        self.shm.buf[0:2] = b"\x00\x00"  # Not paused, not stopped
        self.shm.buf[2:6] = (logging.INFO).to_bytes(4, byteorder="little")

    def cleanup(self):
        """Release shared memory resources."""
        if hasattr(self, "shm") and self.shm:
            try:
                self.shm.close()
                self.shm.unlink()
            except Exception as e:
                logger.error(f"Error cleaning up shared memory: {e}")

    def pause(self):
        """Pause all tasks."""
        self.shm.buf[0] = 1

    def resume(self):
        """Resume all tasks."""
        self.shm.buf[0] = 0

    def stop(self):
        """Stop all tasks."""
        self.shm.buf[1] = 1

    def set_log_level(self, level):
        """Set the log level for all tasks."""
        level_bytes = level.to_bytes(4, byteorder="little")
        self.shm.buf[2:6] = level_bytes

    def get_signal_state(self):
        """Get a signal state object for use in worker processes."""
        return TaskSignalState(self.shared_mem_name)


class ControlledIterator:
    """Wraps an iterator to check control signals between items."""

    def __init__(self, iterable, signal_state):
        self.iterable = iterable
        self.signal_state = signal_state

    def __iter__(self):
        for item in self.iterable:
            # Check for control signals before yielding each item
            if not self.signal_state.check_control():
                break  # Stop iteration if control signal says to stop
            yield item


@contextlib.contextmanager
def controlled_execution(task_signal_manager):
    """Context manager for controlled task execution."""
    signal_state = task_signal_manager.get_signal_state()
    try:
        yield signal_state
    finally:
        signal_state.close()


# Update AsyncDeobfuscator to use the task control system
@dataclasses.dataclass
class AsyncDeobfuscator(AsyncEventEmitter):
    shm_name: str
    data_size: int
    start_ea: int
    is_64bit: bool
    max_workers: int = None

    def __post_init__(self):
        super().__post_init__()
        self.pause_evt = asyncio.Event()
        self.stop_evt = asyncio.Event()
        self.max_workers = self.max_workers or max(1, multiprocessing.cpu_count())
        ctx = multiprocessing.get_context("spawn")
        self.executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=self.max_workers, mp_context=ctx
        )
        # Add task signal manager
        self.task_signal_manager = TaskSignalManager()
        logger.info(f"executor pool created with {self.max_workers} workers")

    def _wrap_task_function(self, fn):
        """Wrap a task function to use controlled execution."""
        task_manager = self.task_signal_manager

        def wrapper(*args, **kwargs):
            with controlled_execution(task_manager) as signal_state:
                # Check log level
                log_level = signal_state.get_log_level()
                logger.setLevel(log_level)

                # Check if we should even start
                if not signal_state.check_control():
                    return []  # Return empty result

                # Replace iterables in args with controlled versions
                new_args = []
                for arg in args:
                    if hasattr(arg, "__iter__") and not isinstance(
                        arg, (str, bytes, bytearray)
                    ):
                        new_args.append(ControlledIterator(arg, signal_state))
                    else:
                        new_args.append(arg)

                # Run the function
                return fn(*new_args, **kwargs)

        return wrapper

    @log_execution_time
    async def stage1(self):
        await self.emit("stage1_started")
        async with self._get_buffer() as buf:
            loop = asyncio.get_running_loop()
            # Wrap the task function
            wrapped_fn = self._wrap_task_function(stage1_find_patterns)
            chains = await loop.run_in_executor(
                self.executor, wrapped_fn, buf, self.start_ea
            )
        await self.emit("stage1_finished", chains)
        return chains

    # Similarly modify other stages to use _wrap_task_function...

    def pause_workers(self):
        """Pause all workers."""
        self.task_signal_manager.pause()
        self.pause_evt.set()

    def resume_workers(self):
        """Resume all workers."""
        self.task_signal_manager.resume()
        self.pause_evt.clear()

    def stop_workers(self):
        """Stop all workers."""
        self.task_signal_manager.stop()
        self.stop_evt.set()

    def set_log_level(self, level):
        """Set the log level for all workers."""
        self.task_signal_manager.set_log_level(level)

    async def shutdown(self):
        self.stop_workers()
        self.executor.shutdown(wait=True)
        self.task_signal_manager.cleanup()
        await self.emit("stopped")


# Update WorkerController to use the new control methods
class WorkerController:
    def __init__(self, deob: AsyncDeobfuscator):
        self.deob = deob
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._result = None
        self._started = False

    # ... existing methods ...

    def pause(self):
        """Pause all workers."""
        if not self._started:
            logger.warning("Pause called before worker controller was started.")
            return
        logger.info("▶️  Pausing...")
        self.loop.call_soon_threadsafe(self.deob.pause_workers)

    def resume(self):
        """Resume all workers."""
        if not self._started:
            logger.warning("Resume called before worker controller was started.")
            return
        logger.info("▶️  Resuming...")
        self.loop.call_soon_threadsafe(self.deob.resume_workers)

    def stop(self):
        """Stop all workers."""
        if not self._started:
            logger.warning("Stop called before worker controller was started.")
            return
        logger.info("🛑  Stopping...")
        self.loop.call_soon_threadsafe(self.deob.stop_workers)

    def set_log_level(self, level):
        """Set the log level for all workers."""
        if not self._started:
            logger.warning("set_log_level called before worker controller was started.")
            logger.setLevel(level)  # Set local log level anyway
            return
        logger.info(f"Setting log level to {level}")
        logger.setLevel(level)  # Set local log level
        self.loop.call_soon_threadsafe(lambda: self.deob.set_log_level(level))
