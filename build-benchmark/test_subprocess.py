import time
import sys
import subprocess
import os


def test_subprocess_pipe():
    # Create a pipe (r: read end, w: write end)
    r_fd, w_fd = os.pipe()

    # Wrap both ends into file objects
    rpipe = os.fdopen(r_fd, 'r')
    wpipe = os.fdopen(w_fd, 'w')

    # Get command to run a child process
    # It writes a message to the write-end of the passed file descriptor
    child_code = """
import os
import sys

fd = int(sys.argv[1])
with os.fdopen(fd, 'w') as f:
   f.write('hello from child\\n')
   f.flush()
"""

    cmd = [sys.executable, "-c", child_code, str(w_fd)]

    try:
        proc = subprocess.Popen(
            cmd,
            # Share the write-end with child
            pass_fds=[w_fd],
            close_fds=False if sys.platform == "win32" else True
        )

        # Close write-end in parent so child has control
        wpipe.close()

        # Read output from the child
        line = rpipe.readline().strip()
        print("Parent received:", line)

        proc.wait()
        print("Child exited with code:", proc.returncode)

    finally:
        rpipe.close()

if __name__ == "__main__":
    test_subprocess_pipe()
