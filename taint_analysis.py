import os
import angr

def perform_taint_analysis(folder_path):
    binary_path = os.path.join(folder_path, "a.out")
    project = angr.Project(binary_path, auto_load_libs=False)
    initial_state = project.factory.entry_state()
    taint_analysis = project.factory.analyses.TaintAnalysis(initial_state=initial_state)
    print("Taint analysis completed.")
