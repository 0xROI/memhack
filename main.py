import os
from compile_and_sanitize import compile_and_sanitize
from parse_source_code import parse_source_code
from symbolic_execution import perform_symbolic_execution
from taint_analysis import perform_taint_analysis
from vulnerability_detection import perform_vulnerability_detection
from generate_report import generate_vulnerability_report

def get_folder_path():
    while True:
        folder_path = input("Please provide the folder path containing the C/C++ source code: ")
        if os.path.exists(folder_path):
            return folder_path
        else:
            print("Folder does not exist. Please provide a valid folder path.")

if __name__ == "__main__":
    folder_path = get_folder_path()
    compile_and_sanitize(folder_path)
    parse_source_code(folder_path)
    perform_symbolic_execution(folder_path)
    perform_taint_analysis(folder_path)
    perform_vulnerability_detection(folder_path)
    generate_vulnerability_report(folder_path)
