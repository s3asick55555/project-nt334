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
import marshal  # For serializing code objects to .pyc format
import struct  # For packing binary data
import sys
import os
import random

class Py_Code(interfaces.plugins.PluginInterface):
    """
    - This plugin extends the Py_Function plugin by analyzing the PyCodeObject data structure associated with functions. 
    - It extracts Python functions bytecode instructions, arguments, local variables, and their names.
    - Particularly useful for understanding the behavior of compiled Python code in memory.

    Requirements:
    - Installed Volatility 3 Framework 
    - Windows Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)

    
    
    Analysis workflow:
      1. Locat the _PyRuntime symbol in the memory dump
      2. Access the garbage collector linked list
      3. Find the root 'sys' module to access the sys.modules dictionary
      4. Examine modules to extract PyFunctionObject instances
      5. Analyze each function's code object (PyCodeObject)
      6. Disassemble the bytecode into human-readable instructions
   
    Usage:
      python3 vol.py -f "path/to/mem dump" windows.py_code.Py_Code--pid=<process_id>
    
    Output:
    - PID: Process ID
    - Func. Name: Name of the function
    - No.Args: Number of arguments the function takes
    - No.Locals: Number of local variables in the function
    - Var Names: Names of the local variables
    - Code: Disassembled bytecode instructions of the function
    
    Note: 
      All plugins  (py_class, py_module, py_func, py_code) share a common initial workflow:
        1. Locating the _PyRuntime address
        2. Traversing the garbage collector
        3. Finding key Python objects
      
      Where they differ is in their specialized analysis methods - this plugin specifically implements 
      the 'process_module' method to extract and analyze PyCodeObject structures, providing detailed
      information about application functions.
    
    """
    
    _version = (1, 0, 0)  # Plugin version
    _required_framework_version = (2, 0, 0) # Minimum Volatility 3 version required



    @classmethod
    def get_requirements(cls):
        """
        Define the requirements for this plugin to run.
        
        The plugin requires:
        - Windows kernel module for memory analysis
        - The PsList plugin to access process information
        - The PESymbolFinder class from pe_symbols plugin to locate _PyRuntime symbol in the dynamic table of PE header
        - A PID identifying the Python process to analyze
        
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
        Create the symbol table and collect Python function information from memory.
    
        This function:
        - Creates the symbol table for Python objects
        - Locates the _PyRuntime address in memory
        - Traverses the garbage collector to find the sys module
        - Uses sys.modules to access all imported modules
        - Focuses on the main module ( '__main__') and expands to other modules to extract their functions
    
        Args:
        tasks: Iterator of process task objects to analyze
        
        Returns:
        list: code data as a list of tuples 
              (pid, function name, number of arguments, number of local variables, names of variables, disassembled bytecode
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

        # Get the _PyRuntime address by calling the above find_py_runtime_address function
        PyRuntime = self.find_py_runtime_address(process)
        
        if not PyRuntime:
          print("Could not find _PyRuntime symbol")
        
        # Offset to the garbage collector head from _PyRuntime
        PYGC_HEAD_OFFSET = 0x170
       
        # Call the 'traverse_GC' function to  traverse the garbage collector to find Python objects"""
        objects = self.traverse_GC(self.context, curr_layer, PyRuntime, PYGC_HEAD_OFFSET, python_table_name)
        collected_data = []
        processed_main = False
        
        # Process  objects found in the garbage collector 
        for obj_info in objects:
            
            if isinstance(obj_info, tuple):
                if len(obj_info) == 3:
                    generation, obj_type, obj = obj_info
                else:
                    print(f"Unexpected tuple length: {len(obj_info)}")
                    continue
            else:
                print(f"Unexpected object type: {type(obj_info)}")
                continue

            obj_address = f"0x{obj.vol.offset:x}"
            if obj_type == 'module':
                module_obj = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyModuleObject",
                    layer_name=curr_layer.name,
                    offset=obj.vol.offset
                )
                # Locate the 'modules'  field in the 'sys' module.
                # Start from the main module as the entry point and expand to other modules in the application.
                
                module_name = module_obj.get_name()
                module_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                if module_dict:
                    if 'modules' in module_dict:
                        sys_modules_obj = module_dict['modules']
                        modules_name = sys_modules_obj.ob_type.dereference().get_name()
                        modules_type = sys_modules_obj.get_type(modules_name)
                        sys_modules_dict_obj = sys_modules_obj.cast_to("PyDictObject")
                        sys_modules_dict = sys_modules_dict_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                        
                        if sys_modules_dict:
                            for modname, modobj in sys_modules_dict.items():
                                if processed_main:
                                    break
                                mod_name = modobj.ob_type.dereference().get_name()
                                mod_type = modobj.get_type(mod_name)
                                
                                if mod_type == 'PyModuleObject':
                                
                                        if modname == "__main__":
                                          modobj = modobj.cast_to("PyModuleObject")
                                          modcollected_data =self.process_module(modobj, python_table_name, process)
                                          collected_data.extend(modcollected_data)
                                          processed_main = True
                                       
                                else:
                                    
                                    
                                    print(f"Skipping object of type {mod_type}, since it's not a module")
                                    continue
            
     

        return collected_data
    
    
    
    def process_module(self, modobj, python_table_name, process):
     
      """
      Process a Python module to extract and disassemble its code objects.
     
      This method examines a module's dictionary to find function objects, and extracts
      information from their code objects including:
      - Function name (co_name)
      - Number of arguments (co_argcount)
      - Number of local variables (co_nlocals)
      - Names of local variables (co_varnames)
      - Disassembled bytecode instructions
    
      It also handles methods defined within classes by examining type objects.
    
      Args:
        modobj: PyModuleObject instance representing the module
        python_table_name: Name of the Python symbol table
        process: Process  object
        
      Returns:
        list: Collection of tuples containing code metadata
             (pid, func_name, num_args, num_locals, var_names, disassembled_code)
      """
      
      try:
        collected_data = []
        # Get the module's dictionary which contains all its objects  
        modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
        if not modobj_dict:
            return collected_data
            
        #  Iterate through each object in the module's dictionary """
        for k, v in modobj_dict.items():
          try:
            #  Get object's memory address as a hex string """
            v_address = f"0x{v.vol.offset:x}"
            # Determine the object type (function, class, etc.) """
            vtype = self.get_value_type(v)
            v_name = v.ob_type.dereference().get_name()
            v_type2 = v.get_type(v_name)
            
            #  Process functions and class methods """
            if vtype=="function" or vtype=="classmethod":
               try:
                   #  Cast the object to a PyFunctionObject to access its fields 
                   func_obj = v.cast_to("PyFunctionObject") 
                   #  Get  the code object  and cast it to PyCodeObject to access its fields 
                   code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
                   code_obj_info = code_obj.to_code_object()
                 
                   if code_obj_info and hasattr(code_obj_info, 'co_code') and code_obj_info.co_code:
                      #  Call the  disassemble_code_with_validation method to disassembly the bytecode
                      disassembled_code = self.disassemble_code_with_validation(code_obj_info)
                   else:
                      disassembled_code = "<unable to extract bytecode>"
                   
                   # Add code information to our results """
                   collected_data.append((
                       int(process.UniqueProcessId), 
                       code_obj_info.co_name if code_obj_info else "unknown", 
                       code_obj_info.co_argcount if code_obj_info else 0, 
                       code_obj_info.co_nlocals if code_obj_info else 0, 
                       code_obj_info.co_varnames if code_obj_info else (),
                       disassembled_code
                   ))
               except Exception as func_err:
                   print(f"Error processing function '{k}': {func_err}")
                   continue
                                                  
            
            # Analyze the function codes of each class in the main module  
            if vtype=="type":
               try:
                   # Process class  codes similar to regular function codes 
                   type_casted = v.cast_to("PyTypeObject")
                   dict_ptr = type_casted.tp_dict
                   if not dict_ptr:
                      continue
                   class_obj = self.context.object(
                       object_type=python_table_name + constants.BANG + "PyDictObject",
                       layer_name=self.process_layer,
                       offset=int(dict_ptr)
                   )
                   class_dict = class_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                   
                   for k1, v1 in class_dict.items():
                      try:
                          v_address1 = f"0x{v1.vol.offset:x}"
                          vtype1 = self.get_value_type(v1)
                          if vtype1=="function" or vtype1=="classmethod": 
                             func_obj = v1.cast_to("PyFunctionObject") 
                             code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
                             code_obj_info = code_obj.to_code_object()

                             if code_obj_info and hasattr(code_obj_info, 'co_code') and code_obj_info.co_code:
                                disassembled_code = self.disassemble_code_with_validation(code_obj_info)
                             else:
                                disassembled_code = "<unable to extract bytecode>"
                                
                             collected_data.append((
                                 int(process.UniqueProcessId), 
                                 code_obj_info.co_name if code_obj_info else "unknown", 
                                 code_obj_info.co_argcount if code_obj_info else 0, 
                                 code_obj_info.co_nlocals if code_obj_info else 0, 
                                 code_obj_info.co_varnames if code_obj_info else (),
                                 disassembled_code
                             ))
                      except Exception as method_err:
                          print(f"Error processing class method '{k1}': {method_err}")
                          continue
               except Exception as class_err:
                   print(f"Error processing class '{k}': {class_err}")
                   continue
          except Exception as item_err:
              print(f"Error processing module item '{k}': {item_err}")
              continue
              
        collected_data.append((int(process.UniqueProcessId), "---------------", "---------------", "---------------","---------------", "---------------",))    
        return collected_data
      except Exception as e:
         print(f"Error processing module in sys.modules: {e}")
         return []
    
    
   
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
      
      # Validate code object
      if not code:
          return "<invalid code object: None>"
      if not hasattr(code, 'co_code'):
          return "<invalid code object: missing co_code>"
      
      instructions = []
      
      def resolve_pyobject(const_obj):
        """Safely resolve Python objects from constants."""
        try:
            if const_obj is None:
                return None
            const_obj_name = const_obj.ob_type.dereference().get_name()
            const_type = const_obj.get_type(const_obj_name)
            if const_type == "PyTupleObject":
               if hasattr(const_obj, 'get_value'):
                    tuple_items = const_obj.get_value()
                    if isinstance(tuple_items, (list, tuple)):
                        return tuple(resolve_pyobject(item) for item in tuple_items)
            if hasattr(const_obj, 'get_value'):
                return const_obj.get_value()
            return str(const_obj)
        except Exception as e:
            return f"<unresolvable>"

      try:
          for instr in self.safe_get_instructions(code):
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
                    if hasattr(code, 'co_consts') and code.co_consts:
                        if instr.arg < len(code.co_consts):
                            const_obj = code.co_consts[instr.arg]
                            argval = resolve_pyobject(const_obj)
                        else:
                            argval = f'<invalid const index {instr.arg}>'
                    else:
                        argval = '<no co_consts>'
                        
                elif instr.opname in dis.hasname:
                    """ Handle named references """
                    if hasattr(code, 'co_names') and code.co_names and isinstance(code.co_names, tuple):
                        if arg < len(code.co_names):
                            argval = code.co_names[arg]
                        else:
                            argval = f'<invalid name index {arg}>'
                    else:
                        argval = '<no co_names>'

                instructions.append(f"{instr.offset}: {opname} {argval}")

            except Exception as e:
                print(f"Error processing instruction: {str(e)[:50]}")
                continue
      except Exception as disasm_err:
          return f"<disassembly failed: {str(disasm_err)[:50]}>"
      
      if not instructions:
          return "<no bytecode instructions found>"
      
      return '\n'.join(instructions)
    
    
    def safe_get_instructions(self,code):
       
      """
      Safely get bytecode instructions from a code object, handling errors.
      
      Args:
          code: A Python code object
          
      Yields:
          Instruction objects or returns on error
      """
      
      try:
        for instr in dis.get_instructions(code):
            yield instr
      except IndexError as e:
        print(f"IndexError during instruction decoding: {str(e)}")
        return 
    

    
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
            cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            return cstring
        except Exception as e:
            print(f"Error reading C string at {hex(address)}: {str(e)}")
            return ""

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

    def traverse_GC(self, context, curr_layer, PyRuntime, PyGC_Head_Offset, python_table_name):
        """
        The garbage collector in Python organizes objects in generations. 
        This method  traverses all generations to find Python objects, locating the root module 'sys' 
        and accessing its 'modules' field that contains all the application modules.
        
        Args:
            context: Volatility context object for memory access
            curr_layer: Current memory layer
            PyRuntime: Address of the _PyRuntime structure
            PyGC_Head_Offset: Offset to the garbage collector head
            python_table_name: Name of the Python symbol table
            
        Returns:
            list: List of tuples containing (generation, type, object) for each object found
        """
        objects = []
        GC_GENERATIONS = 3
        # Traverse each generation of the garbage collector
        for i in range(GC_GENERATIONS):
            # Calculate the address of the generation head (size =24 bytes)

            PyGC_Head = PyRuntime + PyGC_Head_Offset + (i * 24)

            try:
                # Create a PyGC_Head object at the calculated address
                gen_head = context.object(
                    object_type=python_table_name + constants.BANG + "PyGC_Head",
                    layer_name=curr_layer.name,
                    offset=PyGC_Head,
                )
            except Exception as e:
                print(f"Error creating PyGC_Head object for generation {i}: {str(e)}")
                continue

            try:
               
                # Get the address of the next object in the garbage collector
                current_offset = gen_head.get_next()
            except Exception as e:
                print(f"Error accessing _gc_next of gen_head for generation {i}: {str(e)}")
                continue
           
            # Track visited addresses to avoid cycles 
            visited = set()
            visited.add(PyGC_Head)
            gen_object_count = 0
            
            # Traverse the linked list of objects in this generation
            while current_offset != PyGC_Head:
                if current_offset in visited:
                    print(f"Cycle detected at 0x{current_offset:x} in generation {i}")
                    break
               
                visited.add(current_offset)
                # Create a PyObject at the current offset
                try:
                    obj = context.object(
                        object_type=python_table_name + constants.BANG + "PyObject",
                        layer_name=curr_layer.name,
                        offset=current_offset + context.symbol_space.get_type(
                            python_table_name + constants.BANG + "PyGC_Head"
                        ).size,
                    )

                    # Get the object's type and type name
                    obj_type = obj.ob_type.dereference()
                    type_name = obj_type.get_name()
                    
                    # Count the objects per generation
                    gen_object_count += 1
                    
                    # Locate the 'sys' module, once find it, breaks the loop
                    if type_name == 'module':
                       module_obj = obj.cast_to("PyModuleObject")
                       module_name = module_obj.get_name()
                       if module_name == 'sys':
                           objects.append((i, type_name, obj))
                           found_sys = True
                           break
                    
                    # Move to the next object in the linked list
                    current = context.object(
                        object_type=python_table_name + constants.BANG + "PyGC_Head",
                        layer_name=curr_layer.name,
                        offset=current_offset,
                    )
                    current_offset = current.get_next()

                except Exception as e:
                    print("error")
                    break

            print(f"Generation {i} at address: 0x{PyGC_Head:x} has {gen_object_count} objects.")
          

        return objects

    def _generator(self, data):
        # Generate formatted output rows for the UI
        for item in data:
            pid,  func_name, num_args,num_locals,var_names,code = item
            var_names_str = ', '.join(str(x) for x in var_names) if isinstance(var_names, tuple) else str(var_names)
            formatted_code = self.format_code(code)
            # Return  Process ID, function_name, number of arguments, number of locals variables, names of variables, disassembled bytecode 
            yield (0, (
                pid,
                func_name,
                f"{num_args:<10}",
                f"{num_locals:<10}",
                f"{var_names_str:<10}",
                formatted_code
            ))
    
    def format_code(self, code):
        # Format multiline code/values for display
        lines = str(code).split('\n')
        formatted_lines = []
        initial_spacing1 = " " * 10
        initial_spacing2 = " " * 98
        for i, line in enumerate(lines):
            if i > 0:
                formatted_lines.append(f"{initial_spacing2}{line}")
            else:
                formatted_lines.append(f"{initial_spacing1}{line}")
        return '\n'.join(formatted_lines)

    def run(self):
        # Calcualte the total runtime of the plugin
        overall_start_time = time.time()
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
        data_collection_time_end = time.time()
        overall_end_time = time.time()
        total_time = overall_end_time - overall_start_time
        print(f"Total plugin execution time: {total_time:.4f} seconds")
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Func. Name", str),
                ("No.Args", str),
                ("No.Locals", str),
                ("Var Names", str),
                ("                         Code", str)
              
            ],
            self._generator(collected_data)
        )
