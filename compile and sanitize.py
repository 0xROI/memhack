import subprocess
import os

def compile_and_sanitize(folder_path):
    compiler_command = "gcc"  # or use the appropriate compiler command
    sanitizer_flags = [
        "-fsanitize=address",         # AddressSanitizer
        "-fsanitize=undefined",       # Undefined Behavior Sanitizer
        "-fsanitize=memory",          # MemorySanitizer
        "-fsanitize=thread",          # ThreadSanitizer
        "-fsanitize=dataflow",        # DataFlow Sanitizer
        # Add more sanitizer flags as needed
    ]

    compile_command = [compiler_command] + sanitizer_flags + ["-o", "a.out"] + [os.path.join(folder_path, "*.c")]

    try:
        subprocess.run(compile_command, check=True)
        print("Compilation and sanitization completed successfully.")
    except subprocess.CalledProcessError as e:
        print("Compilation and sanitization failed with the following error:")
        print(e)
        raise SystemExit
