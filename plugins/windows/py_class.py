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

class Py_Class(interfaces.plugins.PluginInterface):  
    """
    -  This plugin analyzes the Python application starting from its main entry ( main module '__main__') and extracts all of its objects from memory dumps, 
      providing a comprehensive view of the Python application's state at the acquisition time. 
    
    - It provides the foundation on which other plugins are built.
    - It starts with analyzing the attributes and objects of the main application file and expands to other files. 
    - It focuses on analyzing all the classes in the application and provides details about their attributes, functions, imported modules, 
      variables, and instances.
    
    Requirements:
    - Installed Volatility 3 Framework 
    - Windows Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)


    Analysis workflow:
      1. Locate the _PyRuntime symbol in the memory dump
      2. Access the garbage collector linked list
      3. Traverse all objects in memory, locating the main module, and identifying all of its classes
      4. Extract  attributes, functions, variables, and instances of the main module and all of its classes
    
    This plugin serves as a foundation for more specialized analysis by Py_Module,
    Py_Function, and Py_Code plugins.


    Usage:
    python3 vol.py -f "path/to/mem dump" windows.py_class.Py_Class --pid=<process_id>
    

    Output: 
    - PID: Process ID
    - Gen.: Garbage collector generation number
    - Obj_Type: Type of the Python object (module, function, list, etc.)
    - Obj_Name: Name of the object
    - Obj_Addr: Memory address of the object
    - Obj_Value: Value or representation of the object
    """
     
    _version = (1, 0, 0)  # Plugin version
    _required_framework_version = (2, 0, 0)  # Minimum Volatility 3 version required
    
    @classmethod
    def get_requirements(cls):
        """
        Define the requirements for this plugin to run.
        
        The plugin requires:
        - Windows kernel module for memory analysis
        - PsList plugin to access process information
        - PESymbolFinder (pe_symbols plugin) to locate _PyRuntime symbol
        - PID identifying the Python process to analyze
        
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
        Create the symbol table and collect Python objects from memory.
    
        This function:
          - Creates the symbol table for Python objects using python_data_structures.json
          - Locates the _PyRuntime address in memory
          - Traverses the garbage collector to find Python objects
          - Processes each object to extract its attributes and values
    
        Args:
          processes: Iterator of process  objects to analyze
        
        Returns:
          list: Collected data as list of tuples (pid, generation, obj_type, obj_name, obj_address, obj_value)
        """
        
        # Initialize symbol table for Python objects
        python_table_name = python_Symbol_Table.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures"    
        )

        # Get the process memory layer
        process = next(processes, None)
        if not process:
            return []


        # Get the process memory layer
        proc_layer_name = process.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        self.process_layer = curr_layer.name
        
        
        # Get the _PyRuntime address by calling the above find_py_runtime_address function
        PyRuntime = self.find_py_runtime_address(process)
        
        if not PyRuntime:
          print("Could not find _PyRuntime symbol")
        
        # Offset to the garbage collector head from _PyRuntime
        PYGC_HEAD_OFFSET = 0x170
        
        #Call the 'traverse_GC' function that  traverses the garbage collector to find Python objects
        objects = self.traverse_GC(self.context, curr_layer, PyRuntime, PYGC_HEAD_OFFSET, python_table_name)
       
        collected_data = []
        
        # Process  objects found in the garbage collector (main module + class isntances)
        for obj_info in objects:
            
            if isinstance(obj_info, tuple):
                if len(obj_info) == 3:
                    # For each object, get the generation, type, and info returned by 'traverse_GC' function
                    generation, obj_type, obj = obj_info
                else:
                    print(f"Unexpected tuple length: {len(obj_info)}")
                    continue
            else:
                print(f"Unexpected object type: {type(obj_info)}")
                continue
            
            # Get the object's memory address as a hex string 
            obj_address = f"0x{obj.vol.offset:x}"
            
            # Get the main module of the application
            if obj_type == 'module':
                
                # Create a PyModuleObject from the memory address
                module_obj = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyModuleObject",
                    layer_name=curr_layer.name,
                    offset=obj.vol.offset
                )
                
                # Get the module's name and dictionary
                module_name = module_obj.get_name()
                module_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                if module_dict:
                   
                   #  Process the module's dictionary recursively, where the dictionary might contain nested dictionaries, lists, sets, arrays, etc
                   collected_data=self.recursive_process(module_dict,generation,process,python_table_name,collected_data)
                  
                   # Add a separator line"""
                   collected_data.append((int(process.UniqueProcessId), generation, "-----------------", "--------", "-------------------", "-----------------------"))
           
            # Get all the class isntances that are represented as PyDictObject
            else:  
  
                   try:
                           value=self.process_object_recursively(obj)
                           collected_data.append((int(process.UniqueProcessId), generation, obj_type," ", obj_address, value))
                           collected_data.append((int(process.UniqueProcessId), generation, "-----------------", "--------", "-------------------", "-----------------------"))
                         
                   except Exception as e:
                      print(f"Error reading  instance at {hex(obj.vol.offset)}: {e}")
           

        return collected_data
    
    def recursive_process(self,obj_dict,generation,process,python_table_name,collected_data):
        """
        Recursively process the objects of each class dictionary.
        
        This function: 
        1. Traverses the keys and values of the dictionary
        2. Get the keys that represent the object names and check their value types.
        3. For modules and functions, it returns their names 'k' and addresses as value.
        4. Else, it returns the actual value if the objects by calling 'process_object_recursively' function.
        5. Finally, it returns the pid of the process, generation number, object name 'k', and object value 'vv' of the class objects. 
        
        """

        
        types=[] 
        # Process each key-value pair in the dictionary
        for k, v in obj_dict.items():
                       v_address = f"0x{v.vol.offset:x}"
                       vtype = self.get_value_type(v)
                       v_name = v.ob_type.dereference().get_name()
                       v_type2 = v.get_type(v_name) 
                       # Handle different object types appropriately
                       if vtype == 'module':
                          m_obj = v.cast_to("PyModuleObject")
                          mod_name = m_obj.get_name()
                          vv = f"<'{mod_name}' at {hex(v.vol.offset)}>"
                       elif vtype == 'function' or vtype=='staticmethod' or vtype=='classmethod' or vtype=='code':
                          vv = f"<'{k}' at {hex(v.vol.offset)}>"
                       elif vtype=="type": #  classes are represented as 'PyTypeObject'
                          type_casted = v.cast_to("PyTypeObject")
                          dict_ptr = type_casted.tp_dict
                          vv= f"<'{type_casted.get_name()}' at {hex(v.vol.offset)}>"
                          types.append(v)
                       elif vtype is None:
                          vtype = "Unknown"
                          vv = "None"
                       else:
                          vv = self.process_object_recursively(v)
                       collected_data.append((int(process.UniqueProcessId), generation, vtype, k, v_address, vv))
        collected_data.append((int(process.UniqueProcessId), generation, "---------------------", "---------------------", "---------------------", "---------------------"))
        
        
        #--------------------------------------------------------------------------------------
           # For each  class, we analyze its attributues and objects. 
           # Therefore, we process it similar to the main module by calling 'recursive_process'.
        #--------------------------------------------------------------------------------------
        for t in types:
           #Each  class is represented by the 'PyTypeObject' data structure that contains the class attributes and objects located in tis  'tp_dict' dictionary 
           type_casted = t.cast_to("PyTypeObject")
           dict_ptr = type_casted.tp_dict
           if not dict_ptr:
              return None
           
           class_obj = self.context.object(object_type=python_table_name + constants.BANG + "PyDictObject",layer_name=self.process_layer,offset=int(dict_ptr))
           class_dict = class_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
           self.recursive_process(class_dict,generation,process,python_table_name,collected_data)
                       
        return   collected_data        
    
    
    
    def process_object_recursively(self, obj):
        """
        Extract values from Python objects recursively.
    
        This method handles Python objects of various types (primitives, containers, etc.) and extracts their actual values. 
        For container types like dictionaries and lists, it recursively processes their contents.
    
        Args:
        obj: A Python object in memory
        
        Returns:
         The Python value represented by the object with container contents processed recursively
        """
        # 'get_value' is a method implemented by each Python object class in this module's type system
        if hasattr(obj, 'get_value'): 
            native_val = obj.get_value()
            return self.process_object_recursively(native_val)
        elif isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                new_dict[k] = self.process_object_recursively(v)
            return new_dict
        elif isinstance(obj, (list, set, tuple)):
            return [self.process_object_recursively(x) for x in obj]
        else:
            return obj
    
    
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
        The garbage collector of Python organizes objects in generations. 
        This method  traverses all generations to find Python objects, locating the root module 'sys', 
        accessing its 'modules' field that contains all the application modules,
         and then identifying the main module that represents the  entry point of the application.
        
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
        ransomware_objects = []
        GC_GENERATIONS = 3 # Python uses 3 generations for garbage collection
        class_names = set()
        modules = [] 
        deferred_objects = []
       
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
                    # print(obj)
                    # Get the object's type and type name
                    obj_type = obj.ob_type.dereference()
                    type_name = obj_type.get_name()
                    # Count the objects per generation
                    gen_object_count += 1
                    # Locate the module objects
                    if type_name == 'module':
                        modules.append((i, type_name, obj))
                    #--------------------------------------------------------
                    # Note: we should first identify the classes in the main module (__main__) and 
                    #       then search for their isntances among the other objects of the garbage collector.
                    # Note: Each class isntance has a type name matching its correspnding class. 
                    #--------------------------------------------------------
                    else: # other objects including the class isntances
                    
                        deferred_objects.append((i, type_name, obj))
                    # Move to the next object in the linked list
                    current = context.object(
                        object_type=python_table_name + constants.BANG + "PyGC_Head",
                        layer_name=curr_layer.name,
                        offset=current_offset,
                    )
                    current_offset = current.get_next()

                except Exception as e:
                    print("error: ", e)
                    break
                
            print(f"Generation {i} at address: 0x{PyGC_Head:x} has {gen_object_count} objects.")
        
        
        # Locate 'sys' module and then the '__main__' module in its modules field
        for (i, _, mod_obj) in modules:
                       module_obj = mod_obj.cast_to("PyModuleObject")
                       module_name = module_obj.get_name()
                       if module_name == 'sys':
                           sys_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                           if sys_dict: 
                            
                              if 'modules' in sys_dict: # If sys.modules exists, find __main__
                                  sys_modules_obj = sys_dict['modules']
                                  sys_modules_dict_obj = sys_modules_obj.cast_to("PyDictObject")
                                  sys_modules_dict = sys_modules_dict_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                                  if sys_modules_dict:
                                    for modname, modobj in sys_modules_dict.items():
                                      mod_name = modobj.ob_type.dereference().get_name()
                                      mod_type = modobj.get_type(mod_name)
                                      if mod_type == 'PyModuleObject': 
                                         if modname == "__main__": 
                                             objects.append((i, mod_name, modobj))
                                             modobj = modobj.cast_to("PyModuleObject")
                                             """Access the dictionary associated with the module that contains its objects."""
                                             modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
                                             if modobj_dict:
                                                for k, v in modobj_dict.items():
                                                    vtype = self.get_value_type(v)
                                                    v_name = v.ob_type.dereference().get_name()
                                                    # all the classes (the blueprint, not the instance) are just PyTypeObjects
                                                    if vtype=="type":
                                                       # Identify the classes within the main module
                                                       class_names.add(k)
                                                      
                                                       
                                             
        
       
       
        #--------------------------------------------------------
        # After identifying the classes, we search for any instances of them by looking for objects whose type name matches a class name. 
        # Each class instance has its attributes stored in a dictionary structure.
        #--------------------------------------------------------                       
        for (i, type_name, obj) in deferred_objects: 
                # the type name of the class instance should match its class name
                if type_name in class_names: 
                   objects.append((i, type_name, obj))
        return objects
   
   
    def _generator(self, data):
        #  Generate formatted output rows for the UI
        for item in data:
            pid, generation, obj_type, obj_name, obj_address, obj_value = item
            formatted_code = self.format_code(obj_value)
            yield (0, (
                pid, # Process ID
                generation,# GC Generation
                f"{obj_type:<20}", # Object type, left-aligned
                f"{obj_name:<20}",  # Object name, left-aligned
                f"{obj_address:<20}", # Object address, left-aligned
                formatted_code # Formatted value
            ))



    def format_code(self, code):
        #  Format multiline code/values for display
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
        """ Calcualte the total runtime of the plugin"""
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

       
        """ Collect data from the processes"""
        collected_data = self._collect_data(processes)
        overall_end_time = time.time()
        total_time = overall_end_time - overall_start_time

        print(f"Total plugin execution time: {total_time:.4f} seconds")
        return renderers.TreeGrid(
            [
                ("PID", int),  # Process ID column
                ("Gen.", int), # Generation column
                ("Obj_Type", str), # Object type column
                ("       Obj_Name", str), # Object name column
                ("                Obj_Addr", str), # Object address column
                ("                    Obj_Value", str)  # Object value column
            ],
            self._generator(collected_data)
        )
