import os
import angr

def perform_symbolic_execution(folder_path):
    binary_path = os.path.join(folder_path, "a.out")
    project = angr.Project(binary_path, auto_load_libs=False)
    entry_point = project.loader.main_object.entry
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=entry_point)

    if simulation.found:
        for found_state in simulation.found:
            print("Symbolic execution found a solution:")
            print(found_state.solver.eval(found_state.regs.rax))
    else:
        print("Symbolic execution did not find any solutions.")
