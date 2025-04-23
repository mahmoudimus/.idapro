# worker_script.py
import argparse
import concurrent.futures
import json  # To send structured results back
import logging
import os
import pathlib
import stat
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache

# Configure basic logging for the worker
logging.basicConfig(level=logging.INFO, format="[Worker:%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_python_interpreter():
    """
    Gets the path to a suitable Python interpreter.
    (Same as before, ensures we find a standalone Python executable)

    >>> import pathlib, sys, stat
    >>> interp: pathlib.Path = get_python_interpreter()
    ...
    >>>
    """
    if (
        hasattr(sys, "_base_executable")
        and sys._base_executable
        and "python" in pathlib.Path(sys._base_executable).name.lower()
    ):
        logger.debug(f"Using _base_executable: {sys._base_executable}")
        return pathlib.Path(sys._base_executable)

    base_paths = [
        sys.prefix,
        sys.exec_prefix,
        sys.executable,
    ]
    exe_suffix = ".exe" if os.name == "nt" else ""
    python_name = f"python{exe_suffix}"

    def base_dirs():
        for dirname in map(pathlib.Path, base_paths):
            yield dirname
            yield dirname.parent
            yield dirname.parent.parent

    for dirname in base_dirs():
        for basename in ["", "bin", "python"]:
            interp_path = dirname / basename / python_name
            if not interp_path.exists():
                continue

            if not interp_path.is_file() or not interp_path.is_symlink():
                continue

            if not interp_path.stat().st_mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                continue

            logger.debug(f"Found Python interpreter at: {interp_path}")
            return interp_path

    logger.warning(
        "Could not determine Python interpreter path, falling back to 'python' in PATH."
    )
    return pathlib.Path("python")


def set_multiprocessing_context():
    import multiprocessing

    # --- Multiprocessing Context Setup ---
    current_method = multiprocessing.get_start_method(allow_none=True)
    if current_method != "spawn":
        multiprocessing.set_start_method("spawn", force=True)
    multiprocessing.set_executable(str(get_python_interpreter()))
    # multiprocessing.get_context() or multiprocessing.get_context("spawn")


# --- Processing Logic (Placeholder) ---
# This function runs in a process pool worker.
# It receives shared memory details and an offset/size within the data to process.
# It should *not* rely on global variables set in the main worker process.
def process_chunk(shm_name, data_size, offset, chunk_size):
    """
    Placeholder function to process a chunk of shared memory data.
    This runs in a separate process pool worker.
    """
    import multiprocessing.shared_memory as sm

    try:
        # Attach to the shared memory segment in this new process
        existing_shm = sm.SharedMemory(name=shm_name)
        # Create a view on the relevant chunk
        chunk_view = existing_shm.buf[offset : offset + chunk_size]

        # --- Simulate Processing ---
        # Read bytes from the chunk_view
        # processed_bytes = bytes(chunk_view) # Example: copy the chunk

        # Perform some dummy calculation or transformation on chunk_view
        # For demonstration, let's just return the sum of byte values in the chunk
        # Note: This is trivial. Your actual processing logic goes here.
        result = sum(chunk_view)
        logger.debug(f"Processed chunk at offset {offset}: sum = {result}")

        # Explicitly release the memory view reference BEFORE closing shared memory
        del chunk_view

        # Return results (must be pickleable)
        return {"offset": offset, "sum": result, "chunk_size": chunk_size}

    except Exception as e:
        logger.error(f"Error processing chunk at offset {offset}: {e}", exc_info=True)
        # Return an error indicator or raise
        return {"offset": offset, "error": str(e), "chunk_size": chunk_size}

    finally:
        # Clean up the shared memory view in this worker process
        if existing_shm:
            existing_shm.close()
        # Do NOT unlink shared memory here! Only the creator (parent) unlinks.


def work(args):
    set_multiprocessing_context()
    import multiprocessing
    import multiprocessing.shared_memory as sm

    # set_multiprocessing_context()
    logger.info(
        f"Worker started. Attaching to shared memory '{args.shm_name}' size {args.data_size} bytes."
    )

    # # Attach to the existing shared memory segment in the main worker process
    # existing_shm_main = None  # Initialize for finally block
    # try:
    #     # Assign the opened object to existing_shm_main
    #     existing_shm_main = sm.SharedMemory(name=args.shm_name)
    #     # The data is available via existing_shm_main.buf[:args.data_size]
    #     logger.info("Successfully attached to shared memory.")
    # except FileNotFoundError:
    #     logger.error(
    #         f"Shared memory segment '{args.shm_name}' not found. Parent might not have created it or unlinked too early."
    #     )
    #     sys.exit(1)
    # except Exception as e:
    #     logger.error(f"Failed to attach to shared memory: {e}", exc_info=True)
    #     # Ensure cleanup if attachment fails partially (though unlikely for sm.SharedMemory)
    #     if existing_shm_main:
    #         existing_shm_main.close()
    #     sys.exit(1)

    # --- Main loop: Read commands from stdin ---
    try:
        while True:
            # Read a command line from standard input (sent by the IDA plugin)
            line = sys.stdin.readline()

            # If readline returns empty string, it means EOF (parent closed pipe)
            if not line:
                logger.info("EOF received on stdin, exiting.")
                break

            # Process the command
            command = line.strip()
            logger.info(f"Received command: {command}")

            if command == "ping":
                # Simple ping/pong response
                response = "pong\n"
                sys.stdout.write(response)
                sys.stdout.flush()
                logger.debug("Sent: pong")

            elif command == "process":
                logger.info("Starting data processing...")
                results = []
                chunk_size = 1024 * 1024  # 1 MB
                offsets = range(0, args.data_size, chunk_size)
                executor = None  # Initialize executor variable

                try:
                    # Create the executor instance
                    ctx = multiprocessing.get_context("spawn")
                    executor = ProcessPoolExecutor(mp_context=ctx)

                    # Submit tasks to the pool
                    future_to_chunk = {
                        executor.submit(
                            process_chunk,
                            args.shm_name,
                            args.data_size,
                            offset,
                            min(chunk_size, args.data_size - offset),
                        ): offset
                        for offset in offsets
                    }

                    # Collect results as they complete
                    for future in concurrent.futures.as_completed(future_to_chunk):
                        offset = future_to_chunk[future]
                        try:
                            chunk_result = future.result()
                            results.append(chunk_result)
                        except Exception as exc:
                            logger.error(
                                f"Chunk at offset {offset} generated an exception: {exc}",
                                exc_info=True,
                            )
                            results.append(
                                {"offset": offset, "error": f"Exception: {exc}"}
                            )

                except Exception as e:
                    # Log errors related to executor creation or task submission/retrieval
                    logger.error(
                        f"Error during ProcessPoolExecutor processing: {e}",
                        exc_info=True,
                    )
                    # Still attempt to send an error signal back if possible
                    if not sys.stdout.closed:
                        try:
                            sys.stdout.write("error\n")
                            sys.stdout.write(f"executor_error: {e}\n")
                            sys.stdout.flush()
                        except IOError as ioe:
                            logger.error(
                                f"IOError writing executor error to stdout: {ioe}"
                            )
                    # No 'continue' here, proceed to finally block for potential shutdown

                finally:
                    # Explicitly shut down the executor and wait for workers
                    if executor:
                        logger.debug("Shutting down ProcessPoolExecutor...")
                        # wait=True is default but explicit here for clarity
                        executor.shutdown(wait=True)
                        logger.debug("ProcessPoolExecutor shut down.")

                # --- Now proceed after executor shutdown ---

                # Check if results were collected (might be empty if error occurred before loop)
                if results:
                    logger.info(
                        f"Processing finished. Collected {len(results)} chunk results."
                    )
                    # --- Send Results back to Parent ---
                    try:
                        results_json = json.dumps(results)
                        sys.stdout.write("results_start\n")
                        sys.stdout.write(results_json + "\n")
                        sys.stdout.write("results_end\n")
                        sys.stdout.write(
                            "results_ready\n"
                        )  # Signal completion *after* results
                        sys.stdout.flush()
                        logger.info("Sent results and 'results_ready' signal.")
                    except Exception as e:
                        logger.error(f"Error sending results: {e}", exc_info=True)
                        # Attempt to send error signal if sending results failed
                        if not sys.stdout.closed:
                            try:
                                sys.stdout.write("error\n")
                                sys.stdout.write(f"send_results_error: {e}\n")
                                sys.stdout.flush()
                            except IOError as ioe:
                                logger.error(
                                    f"IOError writing send_results_error to stdout: {ioe}"
                                )
                elif not sys.stdout.closed:
                    # If no results and no prior error message sent, indicate a general processing issue maybe
                    # Or just log it internally. Let's log it.
                    logger.warning(
                        "Processing finished but no results were collected (possibly due to earlier errors)."
                    )
                    # Optionally send a different signal? For now, just don't send results_ready.

            elif command == "exit":
                logger.info("Received 'exit' command, exiting.")
                break  # Exit the loop

            else:
                # Handle unknown commands
                logger.warning(f"Received unknown command: {command}")
                sys.stdout.write(f"unknown_command: {command}\n")
                sys.stdout.flush()

    except Exception as e:
        # Catch any unexpected errors in the main loop
        logger.error(f"Unexpected worker error: {e}", exc_info=True)
        # Signal error back to parent
        # Check if stdout is writable before writing
        if not sys.stdout.closed:
            try:
                sys.stdout.write("error\n")
                sys.stdout.write(f"unexpected_error: {e}\n")
                sys.stdout.flush()
            except IOError as ioe:
                logger.error(f"IOError writing final error to stdout: {ioe}")

    finally:
        # --- Cleanup ---
        logger.info("Worker shutting down. Closing shared memory view.")
        # Close the view on shared memory in this main worker process
        # Do NOT unlink shared memory here! Only the creator (parent) unlinks.
        # This will now correctly close the shared memory view opened at the start

        # if existing_shm_main:
        #     # Get the name *before* closing, just in case
        #     shm_name_to_unregister = existing_shm_main.name

        #     try:
        #         existing_shm_main.close()
        #         logger.debug(
        #             f"Closed main worker view for SHM: {shm_name_to_unregister}"
        #         )
        #     except Exception as e:
        #         logger.error(f"Error closing main SHM handle: {e}", exc_info=True)

        logger.info("Worker finished.")


# --- Main Worker Logic ---
def main():
    parser = argparse.ArgumentParser(description="Worker process for IDA plugin.")
    parser.add_argument("--shm_name", required=True, help="Shared memory segment name")
    parser.add_argument(
        "--data_size", type=int, required=True, help="Size of the data in shared memory"
    )
    # Could add args for processing specifics if needed
    args = parser.parse_args()
    # warnings.filterwarnings(
    #     "ignore",
    #     message=r"resource_tracker: ",
    #     module="multiprocessing.resource_tracker",
    # )
    # warnings.filterwarnings(
    #     "ignore",
    #     message=r"UserWarning:",
    #     module="multiprocessing.resource_tracker",
    # )
    warnings.filterwarnings("ignore")

    work(args)
    # Import the resource_tracker module - still needed internally by multiprocessing
    # from multiprocessing import resource_tracker
    # try:
    #     # Unregister this shared memory segment from the resource_tracker to avoid spurious warnings.
    #     # The plugin owns and unlinks the segment; the worker only attaches and closes its handle.
    #     # This prevents resource_tracker from incorrectly warning about unlinked shared memory on worker exit.
    #     resource_tracker.unregister(args.shm_name, "shared_memory")
    #     logger.debug(f"Unregistered SHM name '{args.shm_name}' from resource_tracker.")
    # except ValueError:
    #     # This might occur if it was already implicitly unregistered or failed registration
    #     logger.warning(
    #         f"SHM name '{args.shm_name}' not found in resource_tracker for unregistration."
    #     )
    # except Exception as e:
    #     # Catch potential errors during unregistration
    #     logger.error(
    #         f"Error unregistering SHM from resource_tracker: {e}", exc_info=True
    #     )


if __name__ == "__main__":
    main()
