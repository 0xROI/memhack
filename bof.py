import angr

def is_buffer_overflow_present(binary_path):
    project = angr.Project(binary_path, auto_load_libs=False)
    entry_point = project.loader.main_object.entry
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=entry_point)

    if simulation.found:
        for found_state in simulation.found:
            # Check if the stack pointer exceeds the allocated stack memory
            if found_state.regs.rsp > initial_state.regs.rsp:
                return True

    return False
