from volatility3.framework import interfaces, renderers, constants
from volatility3.plugins.windows import pe_symbols # Plugin to locate _PyRuntime in the dynamic table in the PE header
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist 
from volatility3.framework import exceptions
from volatility3.framework.symbols.generic.types.python.python_symbol_table import python_Symbol_Table  # process the  Symbol table for Python types
import textwrap # Used for formatting text output
import dis # Used for disassembling Python bytecode
import types
import json # Used for JSON formatting of data structures
import time

class Py_Stack_Var(interfaces.plugins.PluginInterface):
    """
    - This plugin extracts and displays local variable values from Python function frames in the function call stack.
    - It focuses on recovering the actual runtime values of variables within specified function frames.
    - It analyzes the PyFrameObject data structure of the stack frames.
    - Particularly valuable for forensic analysis of malware to extract dynamically generated values and local variable values within the functions.

    Requirements:
    - Installed Volatility 3 Framework 
    - Linux Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)

    
    Analysis workflow:
      1. Locate the _PyRuntime symbol in the memory dump
      2. Access the interpreter state list from _PyRuntime
      3. Traverse thread states and their frame chains
      4. Identify the thread ID and  when a thread frame matching the target function name is found, extract its local variables
      5. Recover variable values from the f_localsplus array in the frame
    
    Usage: 
      python3 vol.py -f"path/to/memory dump" linux.py_stack.Py_Stack_Var --pid=<target_pid> --target-frame=<function_name> [--thread-id=<thread_id>]
    
    Parameters:
    - pid: Process ID of the Python application to analyze
    - target-frame: Name of the specific function frame to extract variable values from
    - thread_id: (Optional) Specific thread ID to analyze (use Py_Stack_Call to identify thread IDs)
    - dump: (Optional) Boolean flag to dump disassembled bytecode associated with the frames to files

    Output:
    - PID: Process ID
    - Function Name: Name of the function frame
    - Variable Name: Name of the local variable
    - Variable Value: Runtime value of the variable at the time of memory acquisition
    """
    _version = (1, 0, 0)  # Plugin version
    _required_framework_version = (2, 0, 0) # Minimum Volatility 3 version required


    @classmethod
    def get_requirements(cls):
        """
        Define the requirements for this plugin to run.
        
        This method specifies the dependencies, inputs, and options for the plugin:
        
        Requirements:
        - kernel: Windows kernel module for memory analysis (Intel64 architecture)
        - pslist: Plugin dependency for accessing process information
        - pe_symbols: Plugin dependency for locating _PyRuntime in the PE header
        - pid: User-provided process ID to analyze
        - target_frame: Name of the function frame to extract variables from
        - thread_id: Specific thread ID to analyze (optional)
        - dump: Optional boolean flag to save disassembly to files
        
        Returns:
            list: Requirements objects that Volatility will use to validate inputs
                  and dependencies before running the plugin
        """
        
        
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
             name="pe_symbols", plugin=pe_symbols.PESymbols, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="PID of the Python process to analyze",
                element_type=int,
                optional=False,
            ),
            requirements.StringRequirement(
            name="target_frame",
            description="Name of the target frame to analyze",
            optional=False
            ),
            requirements.IntRequirement(
            name="thread_id",
            description="Thread ID to analyze (use Py_Stack_Call to identify thread IDs)",
            optional=True
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump disassembly to files",
                default=False,
                optional=True
            ),
        ]

    
    def find_py_runtime_address(self, process):
      """
        This method uses the 'pe_symbols plugin to search for the _PyRuntime global variable, 
        which is the entry point to the Python runtime.
        
        The _PyRuntime structure maintains critical interpreter state information,
        including garbage collection mechanisms and thread management.
        
        Args:
            process: The process  to analyze, 
            module name (python38.dll or python39.dll, or python310.dll,  etc depends on the analyzed Python version)
            
        Returns:
            int: Memory address of _PyRuntime or None if not found
      """
      
      # Get the process layer
      try:
        proc_layer_name = process.add_process_layer()
      except exceptions.InvalidAddressException:
        return None
    
      # Create a filter to find _PyRuntime symbol in the Python DLL
      # This looks for common Python DLL names
      python_dlls = ["python3.dll", "python38.dll", "python39.dll", "python310.dll", "python311.dll", "python312.dll"]
      filter_modules = {}
    
      for dll in python_dlls:
        filter_modules[dll] = {pe_symbols.wanted_names_identifier: ["_PyRuntime"]}
    
      # Get modules from the process
      kernel = self.context.modules[self.config["kernel"]]
      collected_modules = pe_symbols.PESymbols.get_process_modules(
        self.context, 
        kernel.layer_name,
        kernel.symbol_table_name,
        filter_modules
      )
    
      # Find the symbols
      found_symbols, _ = pe_symbols.PESymbols.find_symbols(
        self.context,
        self.config_path,
        filter_modules,
        collected_modules
      )
    
      # Check if we found _PyRuntime
      for module_name, symbols in found_symbols.items():
        for symbol_name, symbol_address in symbols:
            if symbol_name == "_PyRuntime":
                return symbol_address
    
      return None
    
    
    
    
    def _collect_data(self, processes):
        """
        Create the symbol table and collect Python call stack information.
    
        This method sets up the Python symbol table, locates the PyRuntime structure,
        and traverses the interpreter and thread structures to find all execution frames.
    
        Args:
           processes: Iterator of process  objects to analyze
        
        Returns:
          list: Collected data as list of tuples (pid, num_frames, frames_chain, disasm_file)
        """
        python_table_name = python_Symbol_Table.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures"
        )

        process = next(processes, None)
        if not process:
            return []

        proc_layer_name = process.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        self.process_layer = curr_layer.name

      
        target_frame = self.config.get('target_frame')
        #  Get the _PyRuntime address by calling the above find_py_runtime_address function 
        PyRuntime = self.find_py_runtime_address(process)
        
        if not PyRuntime:
          print("Could not find _PyRuntime symbol")
        
        # Offset to the interpreter  head from _PyRuntime
        interpreters_head_offset = 0x20
        interpreters_head = PyRuntime + interpreters_head_offset
    

        collected_data = self.parse_interpreters(
            self.context, curr_layer, interpreters_head, python_table_name, target_frame,process )
        return collected_data

    
    def parse_interpreters(self, context, layer_name, interpreters_head_ptr, python_table_name, target_frame, process):
      """
        This method navigates the linked list of interpreter instances in memory,
        and for each interpreter, examines all thread states and their associated frame chains.
    
        Args:
          context: Volatility context object for memory access
          layer_name: Current memory layer name
          interpreters_head_ptr: Memory address of the interpreters list head
          python_table_name: Name of the Python symbol table
          process: The process object
        
        Returns:
           list: Call stack data as list of tuples (pid, thread_id, num_frames, frames_chain, disasm_file)
        
        Note: A single Python process can contain multiple interpreter instances, each with its own 
              independent state including modules, objects, and thread states. This allows for memory 
              isolation between different execution contexts within the same process. 

      """
      collected_data = []
      process_id = int(process.UniqueProcessId)
      #  Get the thread_id from config 
      thread_id = self.config.get('thread_id', None) 
    
      try:
        # Read the pointer to the first interpreter from memory (8 bytes pointer) 
        interpreter_head_bytes = self.context.layers[self.process_layer].read(interpreters_head_ptr, 8)
        # Convert bytes to integer address value 
        interpreter_head_addr = int.from_bytes(interpreter_head_bytes, byteorder='little', signed=False)
      except exceptions.InvalidAddressException:
        interpreter_head_addr = 0

      if not interpreter_head_addr:
        print("No interpreters found or invalid pointer!")
        return collected_data
      
      # Create the PyInterpreterState object at the head address 
      current_interpreter = self.context.object(
        object_type=python_table_name + constants.BANG + "PyInterpreterState_head",
        layer_name=self.process_layer,
        offset=interpreter_head_addr
      )
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
            # Skip this thread if a specific thread_id was requested and this isn't it
            if thread_id is not None and indx != thread_id:
                # Move to next thread
                next_tstate_addr = int(current_tstate.next)
                if not next_tstate_addr:
                    break
                current_tstate = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyThreadState",
                    layer_name=self.process_layer,
                    offset=next_tstate_addr
                )
                indx += 1
                continue
            # Get the current frame pointer    
            frame_ptr = int(current_tstate.frame)
            if frame_ptr != 0:
                #  Create the frame object 
                frame_obj = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyFrameObject",
                    layer_name=self.process_layer,
                    offset=frame_ptr
                )
                # Parse the frame chain to find the target frame and its variables 
                local_vars = self.parse_frame_chain(frame_obj, target_frame, python_table_name)
                for fun_name, var_name, var_value in local_vars:
                    collected_data.append((process_id, fun_name, var_name, var_value))

            # If we found the requested thread, and processed it, we can break 
            if thread_id is not None and indx == int(thread_id):
                break
            # Move to the next thread state """   
            next_tstate_addr = int(current_tstate.next)
            if not next_tstate_addr:
                break
            current_tstate = self.context.object(
                object_type=python_table_name + constants.BANG + "PyThreadState",
                layer_name=self.process_layer,
                offset=next_tstate_addr
            )
            indx += 1

      if thread_id is not None and not collected_data:
        print(f"No data found for thread ID {thread_id}. Make sure this thread exists (use Py_Stack_Call to see available threads).")
        
      return collected_data

    
    def parse_frame_chain(self, frame_obj, target_frame_name, python_table_name):
        """
        Traverse a chain of frame objects to find the target frame and extract its local variables.
        
        This method follows the linked list of frame objects (f_back) until it finds a frame
        associated with the target function name. Once found, it extracts information about
        local variables and their values from the frame.
        
        Args:
            frame_obj: The PyFrameObject to start traversal from
            target_frame_name: Name of the function frame to extract variables from
            python_table_name: Name of the Python symbol table
            
        Returns:
            list: Tuples of (function_name, variable_name, variable_value) for local variables
        """
        
        
        local_vars = []
        current = frame_obj
        # Traverse the frame chain using f_back pointers 
        while current and current.vol.offset != 0:
            try:
                    code_addr = int(current.f_code)
                
                    code_obj = self.context.object(
                        object_type=python_table_name + constants.BANG + "PyCodeObject",
                        layer_name=self.process_layer,
                        offset=code_addr
                    )
                    code_obj = code_obj.cast_to('PyCodeObject')
                    code_obj_info=code_obj.to_code_object()
                    # Get the function name 
                    funcname = code_obj.co_name.dereference().get_value() 
                    #  Get code object metadata 
                    if funcname==target_frame_name:
                       co_varnames = code_obj.co_varnames.dereference().get_value() # Variable names
                       co_nlocals= code_obj_info.co_nlocals # Number of local variables
                       co_cellvars=code_obj_info.co_cellvars # Cell variables (for closures)
                       co_consts=code_obj_info.co_consts  # Constants in the code
                       lineno = int(current.f_lineno) # Current line number
                       
                       # Access frame state (globals, locals, execution context)
                       frame_globals = current.f_globals_dict 
                       frame_locals = current.f_locals_obj
                       f_executing=current.f_executing
                       f_localsplus=current.f_localsplus 
                       
                       # Extract variable names as Python strings 
                       names=[]
                       for name in co_varnames:
                           names.append(name.get_value())
                       locals_values = self.get_localsplus_values(current, code_obj, python_table_name,names)
                       for name, value in locals_values.items():
                           local_vars.append((funcname, name, value))
            except Exception as e:
                print("error")
               
            # Get the address of the previous frame 
            f_back_addr = int(current.f_back)
            if f_back_addr == 0:
                # We've reached the end of the chain 
                break
            current = self.context.object(
                object_type=python_table_name + constants.BANG + "PyFrameObject",
                layer_name=self.process_layer,
                offset=f_back_addr
            )

        return local_vars

    
    def get_localsplus_values(self, current, code_obj, python_table_name,names):
     """
        Extract local variable values from a frame's f_localsplus array.
        
        In Python, local variables are stored in the f_localsplus array within a frame object.
        This method reads pointers from this array and resolves them to actual PyObject values.
        
        Args:
            current: The PyFrameObject containing the local variables
            code_obj: The PyCodeObject associated with the frame
            python_table_name: Name of the Python symbol table
            names: List of variable names from co_varnames
            
        Returns:
            dict: Dictionary mapping variable names to their values
     """
     
     
     try:
        # Get the code object to access metadata 
        code = code_obj.to_code_object()
        # Get the number of local variables
        nlocals = int(code.co_nlocals)
        # Get the base address of the f_localsplus array where the local variables are exist
        base_addr = current.f_localsplus.vol.offset
        locals_dict = {}
        curr_layer = self.context.layers[self.process_layer]
        
        # Process each local variable slot in the localsplus array 
        for i in range(nlocals):
            try:
                # Get variable name for this index 
                var_name = names[i] if i < len(names) else f"var_{i}"
                # Calculate the slot address and read the pointer value 
                slot_addr = base_addr + (i * 8)
                ptr_bytes = curr_layer.read(slot_addr, 8)
                ptr_value = int.from_bytes(ptr_bytes, byteorder='little')
                
                if ptr_value == 0:
                    value = None
                else:
                    obj = self.context.object(
                        object_type=python_table_name + constants.BANG + "PyObject",
                        layer_name=self.process_layer,
                        offset=ptr_value
                    )
                    
                    # Extract the value of each local variable 
                    value = self.process_object_recursively(obj) 
                locals_dict[var_name] = value
                    
            except Exception as e:
                print(f"Error reading variable at index {i}: {e}")
                
        return locals_dict
        
     except Exception as e:
        print(f"Error getting f_localsplus values: {e}")
        return {}
    
    def process_object_recursively(self, obj):
        """
        Extract values from Python objects recursively.
        
        This method handles Python objects of various types (primitives, containers, etc.)
        and extracts their actual values. For container types like dictionaries and lists,
        it recursively processes their contents.
        
        Args:
            obj: A Python object in memory
            
        Returns:
            The Python value represented by the object (with container contents processed recursively)
        """
        if hasattr(obj, 'get_value'):
            native_val = obj.get_value()
            vtype = self.get_value_type(native_val)
            if vtype =="dict":
               obj=obj.cast_to('PyDictObject')
               obj_dict= obj.get_dict(cur_depth=0, max_depth=100)  
               new_dict = {}
               for k, v in obj_dict.items():
                   new_dict[k] = self.process_object_recursively(v) 
               return new_dict
            
            elif vtype =="set":
                 obj=obj.cast_to('PySetObject')
                 return [self.process_object_recursively(x) for x in obj.get_value()]
          
            elif vtype =="list":
              
                 obj=obj.cast_to('PyListObject')
                 return [self.process_object_recursively(x) for x in obj.get_value()]
                 
            elif vtype =="tuple":
                 obj=obj.cast_to('PyTupleObject')
                 return [self.process_object_recursively(x) for x in obj.get_value()]
          
            else:
               return obj.get_value()

        else:
            return obj
    
  
  
   
   
    def get_value_type(self, value):
        """
        Get the type name of a Python object.
        
        Args:
            value: Python object
            
        Returns:
            str: Type name of the object
        """
        if value is None:
            return 'NoneType'
        if hasattr(value, 'ob_type'):
            try:
                ob_type = value.ob_type.dereference()
                tp_name_ptr = ob_type.tp_name
                type_name = self.read_cstring(tp_name_ptr)
                return type_name.split('.')[-1]
            except Exception as e:
                print(f"Error getting type name of PyObject: {str(e)}")
                return None
        else:
            return type(value).__name__

    def read_cstring(self, address, max_length=256):
        """
        Read a C-style null-terminated string from memory.
        
        Args:
            address: Memory address of the string
            max_length: Maximum number of bytes to read
            
        Returns:
            str: The string read from memory
        """
        
        try:
            data = self.context.layers[self.process_layer].read(address, max_length, pad=False)
            cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')   # Split at null terminator and decode as UTF-8
            return cstring
        except Exception as e:
            print(f"Error reading C string at {hex(address)}: {str(e)}")
            return ""

    def _generator(self, data):
      """
      Generator method for TreeGrid output.
        
      This method formats the collected variable data for display in the Volatility UI,
      including information about which thread the variables came from.
        
      Args:
            data: List of tuples containing variable information
                 (pid, function_name, var_name, var_value)
                 
      Yields:
            Formatted rows for the TreeGrid UI
      """
      
      for item in data:
        pid, fun_name, var_name, var_value = item
        yield (0, (
            pid,
            fun_name,
            str(var_name),  
            "              " + str(var_value)  
        ))
 

    def run(self):
      filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
      kernel = self.context.modules[self.config['kernel']]
      symbol_table = kernel.symbol_table_name
      processes = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=symbol_table,
            filter_func=filter_func
        )


      collected_data = self._collect_data(processes)
      return renderers.TreeGrid([
        ("PID", int),
        ("Function", str),  
        ("Variable Name", str),
        ("Variable Value", str)],
        self._generator(collected_data))
