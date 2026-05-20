from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist 
from volatility3.plugins.linux import elf_symbols # Plugin to locate _PyRuntime in the dynamic table in the ELF header
from volatility3.framework import exceptions
from volatility3.framework.symbols.generic.types.python.python_symbol_table import python_Symbol_Table  # process the  Symbol table for Python types
import textwrap # Used for formatting text output
import dis # Used for disassembling Python bytecode
import types
import json # Used for JSON formatting of data structures
import time
class Py_Stack_Call(interfaces.plugins.PluginInterface):
    """
    - This plugin reconstructs the Python function call stack from memory dumps.
    - It identifies all executing threads and their frame chains and provides detailed execution paths.
    - It analyzes the PyFrameObject data structure of the stack frames.
    - Valuable for tracing the execution flow of Python applications at the time of memory acquisition.

    Requirements:
    - Installed Volatility 3 Framework 
    - Linux Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)

    Analysis workflow:
      1. Locate the _PyRuntime symbol in the memory dump
      2. Access the interpreter state list
      3. For each interpreter, traverse all thread states
      4. For each thread, walk the frame chain linked by f_back pointers
      5. Extract function names, file locations, and line numbers for each frame
      6. Optionally dumping the  disassembled bytecode of the frames to files
    
    Usage: 
      python3 vol.py -f "path/to/mem dump"  linux.py_stack.Py_Stack_Call --pid=<target_pid> [--dump]
   
    Parameters:
    - pid: Process ID of the Python application to analyze
    - dump: (Optional) Boolean flag to dump the  disassembled bytecode to file

    Output:
    - PID: Process ID
    - Thread.Id: Identifier for the thread
    - No.Frames: Number of frames in the call stack
    - Frame Chain: Sequence of function calls with file locations and line numbers
    - Disassembly File: Path to the saved disassembled bytecode file (if --dump is used)
    """
    _version = (1, 0, 0)  # Plugin version
    _required_framework_version = (2, 0, 0) # Minimum Volatility 3 version required

    @classmethod
    def get_requirements(cls):
        
        """
        Define the requirements for this plugin to run.
    
        This method specifies the dependencies, inputs, and options for the plugin:
    
        Requirements:
         - kernel: Linux kernel module for memory analysis (Intel64 architecture)
         - pslist: Plugin dependency for accessing process information
         - elf_symbols: Plugin dependency for locating _PyRuntime in the ELF header
         - pid: User-provided process ID to analyze
         - dump: Optional boolean flag to save the disassembled bytecode to file
    
        Returns:
          list: Requirements objects that Volatility will use to validate inputs
              and dependencies before running the plugin
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
             name="elf_symbols", plugin=elf_symbols.ELFSymbolFinder, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="PID of the Python process to analyze",
                element_type=int,
                optional=False,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump disassembly to files",
                default=False,
                optional=True
            ),
        ]

    
    
    def find_py_runtime_address(self, task):

      """
        This method uses the 'elf_symbols plugin to search for the _PyRuntime global variable, 
        which is the entry point to the Python runtime.
        
        The _PyRuntime structure maintains critical interpreter state information,
        including garbage collection mechanisms and thread management.
        
        Args:
            task: The task (process) object to analyze, 
            module name (python3.8 or python3.9, or python3.10,  etc depends on the analyzed Python version)
            
        Returns:
            int: Memory address of _PyRuntime or None if not found
        """
      
      try:
        # Get the process layer
        proc_layer_name = task.add_process_layer()
       
      except exceptions.InvalidAddressException:
      
        return None
    
      #Identify Python module names for Linux - can be extended for other Python versions
      python_modules = ["python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14"]
  
      for python_module in python_modules:
        
        
        # Create a proper configuration for the plugin
        base_config_path = self.config_path
        plugin_config_path = interfaces.configuration.path_join(base_config_path, "elf_symbol_finder")
        
        #Setup required configuration options
        config_data = {
            interfaces.configuration.path_join(plugin_config_path, "kernel"): self.config["kernel"],
            interfaces.configuration.path_join(plugin_config_path, "module_name"): python_module,
            interfaces.configuration.path_join(plugin_config_path, "symbol"): "_PyRuntime",
            interfaces.configuration.path_join(plugin_config_path, "exact_match"): True,
            interfaces.configuration.path_join(plugin_config_path, "source"): "processes"
        }
        
       
        for key, value in config_data.items():
            #Apply the configuration to the context
            self.context.config[key] = value
        
        try:
            # Instantiate the ELFSymbolFinder class of the elf_symbols plugin
            finder_plugin = elf_symbols.ELFSymbolFinder(self.context, plugin_config_path)
            
            # Run the plugin and extract results
            symbol_found = False
            for depth, result in finder_plugin._generator():
                
                # Check specifically for depth=1 which contains the address info
                if depth == 1 and isinstance(result, tuple) and len(result) > 1:
                    address_info = result[1]
                    
                    # Extract address using string operations
                    if address_info.startswith("Address: 0x"):
                        address_str = address_info[len("Address: 0x"):]
                        try:
                            # Convert hex string to integer
                            address = int(address_str, 16)
                            
                            # Return the _PyRuntime address if found
                            return address
                        
                        except ValueError as ve:
                            # Skip if we can't convert the address
                            continue
            
            if not symbol_found:
                print(f"No _PyRuntime found in {python_module}")
            
        except Exception as e:
            print(f"Error searching for _PyRuntime in {python_module}: {e}")
      print("Could not find _PyRuntime symbol in any Python module")
      return None
    
    
    def _collect_data(self, tasks):
        """
        Create the symbol table and collect Python call stack information.
    
        This method sets up the Python symbol table, locates the PyRuntime structure,
        and traverses the interpreter and thread structures to find all execution frames.
    
        Args:
           tasks: Iterator of process task objects to analyze
        
        Returns:
          list: Collected data as list of tuples (pid, thread_id, num_frames, frames_chain, disasm_file)
        """
        python_table_name = python_Symbol_Table.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures"
        )

        # Safely get the first task
        task = next(tasks, None)
        if not task:
            return []

       
        task_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[task_layer_name]
        self.process_layer = curr_layer.name
        # Get the _PyRuntime address by calling the above find_py_runtime_address function 
        PyRuntime = self.find_py_runtime_address(task)
        
        if not PyRuntime:
          print("Could not find _PyRuntime symbol")
        
        # Offset to the interpreter  head from _PyRuntime"""
        interpreters_head_offset = 0x20
        interpreters_head = PyRuntime + interpreters_head_offset
     

        collected_data = self.parse_interpreters(
            self.context, curr_layer, interpreters_head, python_table_name, task
        )
        return collected_data

    def parse_interpreters(self, context, layer_name, interpreters_head_ptr, python_table_name, task):
        """
        This method navigates the linked list of interpreter instances in memory,
        and for each interpreter, examines all thread states and their associated frame chains.
    
        Args:
          context: Volatility context object for memory access
          layer_name: Current memory layer name
          interpreters_head_ptr: Memory address of the interpreters list head
          python_table_name: Name of the Python symbol table
          task: The task (process) object
        
        Returns:
           list: Call stack data as list of tuples (pid, thread_id, num_frames, frames_chain, disasm_file)
        
        Note: A single Python process can contain multiple interpreter instances, each with its own 
              independent state including modules, objects, and thread states. This allows for memory 
              isolation between different execution contexts within the same process. 

        """
        collected_data = []

        try:
            # Read the pointer to the first interpreter from memory (8 bytes pointer) 
            interpreter_head_bytes = self.context.layers[self.process_layer].read(interpreters_head_ptr, 8)
            # Convert bytes to integer address value """
            interpreter_head_addr = int.from_bytes(interpreter_head_bytes, byteorder='little', signed=False)
        except exceptions.InvalidAddressException:
            interpreter_head_addr = 0

        if not interpreter_head_addr:
            print("No interpreters found or invalid pointer!")
            return collected_data
        # Create the PyInterpreterState object at the head address 
        current_interpreter = self.context.object(object_type=python_table_name + constants.BANG + "PyInterpreterState_head",layer_name=self.process_layer,  offset=interpreter_head_addr   )
        # List to store all interpreter objects 
        interpreters = []
       
        # Traverse the linked list of interpreters 
        while current_interpreter and current_interpreter.vol.offset != 0:
            #  Add the current interpreter to our list 
            interpreters.append(current_interpreter)
            #  Get the address of the next interpreter in the chain 
            next_addr = int(current_interpreter.next)
            
            #  Break if we've reached the end of the list 
            if not next_addr:
                break
            # Move to the next interpreter 
            current_interpreter = self.context.object(
                object_type=python_table_name + constants.BANG + "PyInterpreterState_head",
                layer_name=self.process_layer,
                offset=next_addr
            )

        
        # Process each interpreter to extract thread states
        for interp in interpreters:
            # Get the pointer to the first thread state in this interpreter 
            tstate_head_addr = int(interp.tstate_head)
            if tstate_head_addr == 0:
                #  Skip if the interpreter has no thread states 
                continue

            
            # Create the PyThreadState object for the head thread 
            current_tstate = self.context.object(
                object_type=python_table_name + constants.BANG + "PyThreadState",
                layer_name=self.process_layer,
                offset=tstate_head_addr
            )

            #  Thread index counter for this interpreter
            indx = 0
            # Traverse the linked list of thread states 
            while current_tstate and current_tstate.vol.offset != 0:
                #  Get the pointer to the current frame for this thread
                frame_ptr = int(current_tstate.frame)
                if frame_ptr != 0:
                    # Create the PyFrameObject for the current frame 
                    frame_obj = self.context.object(
                        object_type=python_table_name + constants.BANG + "PyFrameObject",
                        layer_name=self.process_layer,
                        offset=frame_ptr
                    )
                    # Parse and store call-stack info for this thread"""
                    frames, num_frames = self.parse_frame_chain(frame_obj, python_table_name)
                    # Reverse frames so oldest is first in the chain (most recent frame is processed first) 
                    frames.reverse()  

                    # Use UniqueProcessId 
                    task_id = int(task.pid)

                    # If user wants to dump disassembly to files, prepare filename 
                    disasm_file = f"chain_thread_{indx}_{task_id}_disassembly.txt" if self.config.get('dump', False) else "disabled"
                    if self.config.get('dump', False):
                        # Save the disassembly to a file if requested 
                        self.save_chain_disassembly(frames, task_id, indx)

                    # Build a human-readable chain for the TreeGrid display
                    print_full_chain_value, num_frames = self.print_full_chain(frame_obj, python_table_name)
                    collected_data.append((task_id, indx, num_frames, print_full_chain_value, disasm_file))

                next_tstate_addr = int(current_tstate.next)
                if not next_tstate_addr:
                    break
                current_tstate = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyThreadState",
                    layer_name=self.process_layer,
                    offset=next_tstate_addr
                )
                indx += 1

        return collected_data

    def parse_frame_chain(self, frame_obj, python_table_name):
        """
        Extract frame information by traversing the chain of frame objects.
    
        This method follows the linked list of frame objects using the f_back pointers,
        extracting information about each frame including the function name, source file, 
        line number, and bytecode disassembly.
    
        Args:
          frame_obj: The starting PyFrameObject
          python_table_name: Name of the Python symbol table
        
        Returns:
          tuple: (List of frame dictionaries, Number of frames found)
              Each frame dictionary contains filename, funcname, lineno, and disassembly
        """
        frames = []
        num_frames = 0
        current = frame_obj

        while current and current.vol.offset != 0:
            try:
                """ Extract information from the frame's code object"""
                code_addr = int(current.f_code)
                if code_addr == 0:
                    frames.append({
                        "filename": "<unknown>",
                        "funcname": "<unknown>",
                        "lineno": 0,
                        "disassembly": "[No code object]"
                    })
                else:
                    
                    #  Get  the code object  and cast it to PyCodeObject to access its fields 
                    code_obj = self.context.object(
                        object_type=python_table_name + constants.BANG + "PyCodeObject",
                        layer_name=self.process_layer,
                        offset=code_addr
                    )
                    code_obj = code_obj.cast_to('PyCodeObject')
                    code_obj_info=code_obj.to_code_object()                             
                    # Get code attributes from its fields 
                    filename = code_obj.co_filename.dereference().get_value()  # Source file path
                    funcname = code_obj.co_name.dereference().get_value() # Function name
                    co_varnames = code_obj.co_varnames.dereference().get_value() # Names of local variables 
                    co_nlocals= code_obj_info.co_nlocals #  Number of local variables
                    co_cellvars=code_obj_info.co_cellvars   # Cell variables for closures
                    co_consts=code_obj_info.co_consts  # Constants used in the code
                    lineno = int(current.f_lineno)  # Current line number in execution
                    
                    # Access frame state (globals, locals, execution context
                    frame_globals = current.f_globals_dict # Global variables dictionary
                    frame_locals = current.f_locals_obj  # Local variables dictionary
                    f_executing=current.f_executing # Execution state
                    
                    f_localsplus=current.f_localsplus # Array of local variables
                    # Disassemble the bytecode for this frame 
                    disassembly = self.disassemble_bytecode(code_obj) or "[No disassembly]"
                    #  Add the frame information to our list 
                    frames.append({
                        "filename": filename,
                        "funcname": funcname,
                        "lineno":lineno,
                        "disassembly": disassembly
                    })
                    
                    num_frames += 1
            except Exception as e:
                frames.append({
                    "filename": "<error>",
                    "funcname": "<error>",
                    "lineno": -1,
                    "disassembly": f"[Error retrieving frame info: {e}]"
                })
                
            # Get the address of the previous frame 
            f_back_addr = int(current.f_back)
            if f_back_addr == 0:
                # We've reached the end of the chain 
                break
            
            # Move to the previous frame """
            current = self.context.object(
                object_type=python_table_name + constants.BANG + "PyFrameObject",
                layer_name=self.process_layer,
                offset=f_back_addr
            )

        return frames, num_frames


    
    def print_full_chain(self, frame_obj, python_table_name):
        """
        Create a human-readable representation of the frame chain.
    
        Builds a string that shows the execution path from the oldest frame to the newest,
        in the format: func1(file1:line1) --> func2(file2:line2) --> ...
    
        Args:
          frame_obj: The starting PyFrameObject
          python_table_name: Name of the Python symbol table
        
        Returns:
          tuple: (String representation of the call chain, Number of frames)
        """
        frames, num_frames = self.parse_frame_chain(frame_obj, python_table_name)
        frames.reverse()  # oldest to newest
        chain_parts = []
        for f in frames:
            func = f["funcname"]
            full_path = f["filename"]
            filename = full_path.split('/')[-1] if '/' in full_path else full_path
            lineno = f["lineno"]
            chain_parts.append(f"{func}({filename}:{lineno})")

        chain_str = " --> ".join(chain_parts)
        return chain_str, num_frames

    def disassemble_bytecode(self, code_obj):
        """
        Convert the PyCodeObject into a Python code object and disassemble its bytecode by calling 'disassemble_code_with_validation'.
    
        This method reconstructs a live Python code object from its memory representation
        and converts its bytecode into human-readable instructions.
    
        Args:
          code_obj: The PyCodeObject to disassemble
        
        Returns:
          str: Disassembled bytecode as a string or None on error
        """
      
        try:
            code_obj = code_obj.cast_to("PyCodeObject")
            code = code_obj.to_code_object()

            if code and hasattr(code, 'co_code') and code.co_code:
                disassembled_code = self.disassemble_code_with_validation(code)
                return disassembled_code
            else:
                print(f"Failed to reconstruct code object at {hex(code_obj.vol.offset)}")
                return None
        except Exception as e:
            print(f"Exception during disassembly of code object at {hex(code_obj.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def disassemble_code_with_validation(self, code):
        """
        Disassemble code with validation for robustness.
      
        This method carefully handles each instruction and resolves any references
        to constants, names, etc. with proper error handling.
      
        Args:
          code: A Python code object
          
        Returns:
          str: Disassembled code as a string of instructions
          
        Note: Each bytecode instruction contains multiple attributes:
        - opname: Human-readable operation name (e.g., 'LOAD_GLOBAL', 'CALL_FUNCTION')
        - opcode: Numeric identifier for the operation (e.g., 116 for LOAD_GLOBAL)
        - arg: Numeric value used as an index or immediate value (e.g., 0)
        - argval: The actual value the arg refers to (e.g., 'print')
        - argrepr: String representation of argval (e.g., 'print')
        - offset: Byte position of instruction in the bytecode sequence (e.g., 0)
        - starts_line: Source code line number (e.g., 53)
        - is_jump_target: Whether this instruction is a jump destination (e.g., False)
    

        """
        instructions = []

        def resolve_pyobject(const_obj):
            const_obj_name = const_obj.ob_type.dereference().get_name()
            const_type = const_obj.get_type(const_obj_name)
            if const_type == "PyTupleObject":
                if hasattr(const_obj, 'get_value'):
                    tuple_items = const_obj.get_value()
                    if isinstance(tuple_items, (list, tuple)):
                        return tuple(resolve_pyobject(item) for item in tuple_items)
                    else:
                        raise ValueError("Unexpected value type in PyTupleObject")

            if hasattr(const_obj, 'get_value'):
                return const_obj.get_value()
            return str(const_obj)

        def safe_get_instructions(c):
            import dis
            try:
                for instr in dis.get_instructions(c):
                    yield instr
            except IndexError as e:
                print(f"IndexError during instruction decoding: {str(e)}")
                return

        for instr in safe_get_instructions(code):
            try:
                opname = instr.opname
                argval = instr.argval if instr.argval is not None else ''
                arg = instr.arg if instr.arg is not None else 0

                if instr.opname == "LOAD_CONST":
                    """
                    The constants loaded by LOAD_CONST can be any Python objects stored in the code object's
                    co_consts tuple, including primitives (int, float, str, bool, None), containers (tuples, 
                    lists), and even nested code objects for inner functions or comprehensions. The constant
                    at the given index needs to be properly resolved based on its specific type.
                    """
                    if instr.arg < len(code.co_consts):
                        const_obj = code.co_consts[instr.arg]
                        argval = resolve_pyobject(const_obj)
                    else:
                        argval = f'<invalid const index {instr.arg}>'

                elif instr.opname in dis.hasname:
                    """ Handle named references """
                    if isinstance(code.co_names, tuple) and arg < len(code.co_names):
                        argval = code.co_names[arg]
                    else:
                        argval = f'<invalid name index {arg}>'

                instructions.append(f"{instr.offset}: {opname} {argval}")
            except Exception as e:
                print(f"Error processing instruction at offset {instr.offset}: {str(e)}")
                continue

        return '\n'.join(instructions)

    def save_chain_disassembly(self, frames, task_id, thread_id):
        """
        Save the complete disassembly of all frames to a file.
    
        When the --dump option is specified, this method writes the  disassembled bytecode associated 
        with each frame in the call chain to a file, which can be used for
        deeper analysis of the bytecode.
    
        Args:
          frames: List of frame dictionaries
          task_id: Process ID
          thread_id: Thread ID
        """
        if not self.config.get('dump', False):
            return

        filename = f"chain_threads_{task_id}_{thread_id}_disassembly.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"Disassembly for Thread {thread_id} (PID {task_id}) Call Chain\n")
                f.write("=" * 50 + "\n\n")

                for idx, frame in enumerate(frames):
                    funcname = frame["funcname"]
                    fname = frame["filename"]
                    if '/' in fname:
                        fname = fname.split('/')[-1]
                    lineno = frame["lineno"]
                    disassembly = frame["disassembly"]
                    f.write(f"Frame {idx}: {funcname} in {fname} at line {lineno}\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Disassembly:\n{disassembly}\n")
                    f.write("\n" + "=" * 40 + "\n\n")
                    
        except Exception as e:
            print(f"Error saving disassembly: {str(e)}")

    def _generator(self, data):
        """
        Generator method for TreeGrid output.
        """
        for item in data:
            pid, thread_id, num_frames, frames_chain, disasm_file = item
            formatted_chain = self.format_chain(frames_chain)
            formatted_thread_id = f"        {thread_id}"
            formatted_num_frames = f"        {num_frames}"
            formatted_disasm_file = f"        {disasm_file}"

            yield (0, (
                pid,
                formatted_thread_id,
                formatted_num_frames,
                formatted_chain,
                formatted_disasm_file
            ))

    def format_chain(self, chain):
        """
        Format the call chain string for display in the console.
    
        This method takes a call chain string and formats it with proper indentation
        and arrow symbols to create a visual representation of the call hierarchy.
    
        Args:
          chain: String representation of the call chain
        
        Returns:
          str: Formatted chain string with proper indentation and formatting
        """
        steps = chain.split(' --> ')
        formatted_steps = []
        initial_spacing1 = " " * 10
        initial_spacing2 = " " * 50
        for i, step in enumerate(steps):
            if i > 0:
                prefix = "→ "
                formatted_steps.append(f"{initial_spacing2}{prefix}{step}")
            else:
                prefix = " "
                formatted_steps.append(f"{initial_spacing1}{prefix}{step}")
        return '\n'.join(formatted_steps)

    def run(self):
        """
        Main entry point for the plugin: sets up the filter, enumerates processes, and calls _collect_data.
        """
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func
        )


        # Collect data
        collected_data = self._collect_data(tasks)

        # Return the TreeGrid with collected data
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("   Thread.Id", str),
                ("   No.Frames", str),
                ("             Frame Chain", str),
                ("                 Disassembly File", str)
            ],
            self._generator(collected_data)
        )

