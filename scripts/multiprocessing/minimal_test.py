import multiprocessing
import os
import pathlib
import platform  # Keep for logging
import sys
import time
import traceback

# --- Configuration ---

# Directly use the specified path construction
prefix_path = pathlib.Path(sys.exec_prefix)
specific_python_path = prefix_path / "bin" / "python"

# --- Check if the specified path exists ---
print(f"PARENT: Using sys.exec_prefix: {prefix_path}")
print(f"PARENT: Constructed specific path: {specific_python_path}")

if specific_python_path.exists() and specific_python_path.is_file():
    print(f"PARENT: Confirmed specific path exists and is a file.")
    PYTHON_EXECUTABLE = str(specific_python_path)
else:
    print(
        f"PARENT: ERROR - The specific path '{specific_python_path}' does not exist or is not a file."
    )
    PYTHON_EXECUTABLE = None  # Set to None if invalid

# Define where to write the error log
STDERR_LOG_PATH = pathlib.Path("./worker_stderr_specific_path.log")


# --- Simple target function (same as before) ---
def simple_worker_task():
    print(f"WORKER (PID: {os.getpid()}): Hello from worker!", flush=True)
    print(f"WORKER (PID: {os.getpid()}): Exiting normally.", flush=True)


# --- Wrapper function for redirection (same as before) ---
def worker_wrapper(log_path):
    try:
        sys.stderr = open(log_path, "w", encoding="utf-8")
        simple_worker_task()
    except Exception as e:
        print(f"WORKER WRAPPER EXCEPTION: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        if sys.stderr and not sys.stderr.closed:
            sys.stderr.flush()


# --- Main execution block (important for spawn) ---
if __name__ == "__main__":
    print(f"PARENT (PID: {os.getpid()}): Script started.")

    if PYTHON_EXECUTABLE is None:
        print(
            "PARENT: Exiting because the specified Python executable path is invalid."
        )
        sys.exit(1)  # Exit the script if the path is bad

    print(f"PARENT: Using Python executable: {PYTHON_EXECUTABLE}")

    # Delete old log file
    if STDERR_LOG_PATH.exists():
        try:
            STDERR_LOG_PATH.unlink()
            print(f"PARENT: Removed old log file: {STDERR_LOG_PATH}")
        except OSError as e:
            print(f"PARENT: Warning - Could not remove old log file: {e}")

    try:
        # --- Setup multiprocessing ---
        multiprocessing.set_executable(PYTHON_EXECUTABLE)
        try:
            multiprocessing.set_start_method("spawn", force=True)
            print("PARENT: Set start method to 'spawn'.")
        except ValueError:  # Already set
            current_method = multiprocessing.get_start_method()
            print(f"PARENT: Start method already set to '{current_method}'.")
            if current_method != "spawn":
                print("PARENT: ERROR - Start method not 'spawn', script might fail.")
                sys.exit(1)

        # --- Create and start the process ---
        print("PARENT: Creating Process object...")
        p = multiprocessing.Process(target=worker_wrapper, args=(STDERR_LOG_PATH,))

        print("PARENT: Starting process...")
        p.start()

        # --- Wait for the process to complete ---
        print(f"PARENT: Waiting for process {p.pid if p.pid else '?'} to finish...")
        p.join(timeout=10)  # Wait up to 10 seconds

        # --- Check the outcome ---
        if p.is_alive():
            print(f"PARENT: Process {p.pid} is still alive, terminating.")
            p.terminate()
            p.join(timeout=2)  # Give terminate time
        exit_code = (
            p.exitcode
            if hasattr(p, "exitcode") and p.exitcode is not None
            else "Unknown/Terminated"
        )
        print(f"PARENT: Process finished. Exit code: {exit_code}")

        # --- Check the stderr log file ---
        if STDERR_LOG_PATH.exists():
            print(f"PARENT: Reading worker stderr log: {STDERR_LOG_PATH}")
            try:
                with open(STDERR_LOG_PATH, "r", encoding="utf-8") as f_err:
                    stderr_content = f_err.read()
                if stderr_content:
                    print("------ Worker stderr START ------")
                    print(stderr_content)
                    print("------- Worker stderr END -------")
                else:
                    print("PARENT: Worker stderr log is empty.")
            except Exception as e:
                print(f"PARENT: Error reading stderr log: {e}")
        else:
            print(f"PARENT: Worker stderr log file not found ({STDERR_LOG_PATH}).")

    except Exception as e:
        print(f"PARENT: An error occurred in the main script: {e}")
        traceback.print_exc()

    print("PARENT: Script finished.")
