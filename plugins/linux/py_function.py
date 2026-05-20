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

class Py_Function(interfaces.plugins.PluginInterface):
    """
    - This plugin identifies and analyzes Python functions from memory dumps.
    - It extracts information about functions including their names, parent modules, and source file locations.
    - Useful for identifying suspicious or malicious functions in Python-based malware.

   
    Requirements:
    - Installed Volatility 3 Framework 
    - Windows Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)

    Analysis workflow:
      1. Locate the _PyRuntime symbol in the memory dump
      2. Access the garbage collector linked list
      3. Find the 'sys' module to access the sys.modules dictionary
      4. Examine modules to extract PyFunctionObject
      5. For each module, call the 'process_module' method to analyze each function's metadata and properties
    
   
    Usage:
      python3 vol.py -f "path/to/mem dump" windows.py_function.Py_Function --pid=<process_id>
    
    Output:
    - PID: Process ID
    - Func. Address: Memory address of the function
    - Func. Name: Name of the function
    - Module Name: Name of the module containing the function
    - File Name: Source file containing the function definition
   
    Note: 
      All plugins  (py_class, py_module, py_func, py_code) share a common initial workflow:
        1. Locating the _PyRuntime address
        2. Traversing the garbage collector
        3. Finding key Python objects
      
      Where they differ is in their specialized analysis methods - this plugin specifically implements 
      the 'process_module' method to extract and analyze PyFunction Object structures, providing detailed
      information about application functions.
    """
    _version = (1, 0, 0)  # Plugin version
    _required_framework_version = (2, 0, 0) # Minimum Volatility 3 version required


    @classmethod
    def get_requirements(cls):
        """
        Define the requirements for this plugin to run.
        
        The plugin requires:
        - Linux kernel module for memory analysis
        - The PsList plugin to access process information
        - The ELFSymbolFinder class from elf_symbols plugin to locate _PyRuntime symbol in the dynamic table of ELF header
        - A PID identifying the Python process to analyze
        
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
        Create the symbol table and collect Python function information from memory.
    
        This function:
         - Creates the symbol table for Python objects
         - Locates the _PyRuntime address in memory
         - Traverses the garbage collector to find the sys module
         - Uses sys.modules to access all imported modules
         - Focuses on processing '__main__' as the entry point and expand to other modules to extract their functions
    
        Args:
         tasks: Iterator of task  objects to analyze
        
        Returns:
         list: Function data as list of tuples 
              (pid, function_address, function_name, module_name, file_name)
        """
        python_table_name = python_Symbol_Table.create(self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures")

        task = next(tasks, None)
        if not task:
            return []

        # Get the process memory layer
        task_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[task_layer_name]
        self.process_layer = curr_layer.name
        
        # Get the _PyRuntime address by calling the above find_py_runtime_address function
        PyRuntime = self.find_py_runtime_address(task)
        
        if not PyRuntime:
          print("Could not find _PyRuntime symbol")
        
        
        # Offset to the garbage collector head from _PyRuntime
        PYGC_HEAD_OFFSET = 0x170
    
        # Call the 'traverse_GC' function to  traverse the garbage collector to find Python objects
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
                                            modcollected_data =self.process_module(modobj, python_table_name, task)
                                            collected_data.extend(modcollected_data)
                                            processed_main= True
                                   
                                else:
                                    continue
            
     

        return collected_data

   
    
    def process_module(self, modobj, python_table_name, task):
      
      """
        Process a Python module to extract its functions.
    
        This method examines a module's dictionary to find function objects, and extracts
        key information about each function including:
        - Function name (from func_name_obj)
        - Parent module (from func_module_obj)
        - Source file location (from func_globals['__loader__.path'])
        - Memory address of the function
    
        It also handles functions defined within classes by examining type objects.
    
        Args:
        modobj: PyModuleObject instance representing the module
        python_table_name: Name of the Python symbol table
        task: task  object
        
        Returns:
          list: Collection of tuples containing function metadata
              (pid, function_address, function_name, module_name, file_name)
      """
      try:
        
        collected_data = []
        # Get the module's dictionary which contains all its objects 
        modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
        if modobj_dict:
           #  Iterate through each object in the module's dictionary 
           for k, v in modobj_dict.items():
            #  Get object's memory address as a hex string 
            v_address = f"0x{v.vol.offset:x}"
            # Determine the object type (function, class, etc.) 
            vtype = self.get_value_type(v)
            v_name = v.ob_type.dereference().get_name()
            v_type2 = v.get_type(v_name)
            #  Process functions and class methods 
            if vtype=="function" or vtype=="classmethod":
              
               # Cast the object to a PyFunctionObject to access its fields 
               func_obj = v.cast_to("PyFunctionObject")
               # Get the function's code object which contains bytecode 
               code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
               
               # Get function attributes from its fields
               func_name_obj=func_obj.func_name_obj # Function name
               func_globals_obj= func_obj.func_globals_obj  # Function globals (includes __loader__)
               func_defaults_obj=func_obj.func_defaults_obj # Default parameter values
               func_dict_obj=func_obj.func_dict_obj  # Function's __dict__
               func_module_obj= func_obj.func_module_obj # Parent module
               func_qualname_obj= func_obj.func_qualname_obj  # Qualified name (with class prefix)
               
              
               # Determine types of key attributes 
               func_name_obj_type = self.get_value_type(func_name_obj)
               func_module_obj_type = self.get_value_type(func_module_obj)
               func_qualname_obj_type = self.get_value_type(func_qualname_obj)
               
               # Cast dictionary objects to PyDictObject to access their contents 
               func_globals_dict = func_globals_obj.cast_to("PyDictObject")
               func_defaults_dict = func_defaults_obj.cast_to("PyDictObject")
               func_dict_dict = func_dict_obj.cast_to("PyDictObject")
               
               #  Get the actual dictionaries from these objects """
               func_globals=func_globals_dict.get_dict(cur_depth=0, max_depth=100, visited=set())
               func_defaults=func_defaults_dict.get_dict(cur_depth=0, max_depth=100, visited=set())
               func_dict=func_dict_dict.get_dict(cur_depth=0, max_depth=100, visited=set())
               
               # Extract the file path from the function's globals 
               try:
                   loader=func_globals['__loader__']
                   if loader is not None:
                       loader_type=self.get_value_type(loader)
                       if loader_type=="SourceFileLoader":
                          loader_dict=loader.get_value().get_dict(cur_depth=0, max_depth=100, visited=set())
                          if 'path' in loader_dict:
                              path_obj = loader_dict['path']
                              file_name_value = path_obj.get_value()
               except KeyError:
                 
                   file_name_value = "<unknown file>"
               except Exception as e:
                  
                   print(f"Error getting file name: {e}")
                   file_name_value = "<error>"
               # Add function information to our results """
               collected_data.append((int(task.pid), v_address, func_name_obj.get_value(), func_module_obj.get_value(), file_name_value))
           
            # Analyze the functions of each class in the main module    
            if vtype=="type":
               # Cast the object to a PyTypeObject to access its fields 
               type_casted = v.cast_to("PyTypeObject")
               # Get the class's dictionary pointer (contains methods
               dict_ptr = type_casted.tp_dict
               if not dict_ptr:
                  return []
               #  Create a dictionary object from the pointer 
               class_obj = self.context.object(object_type=python_table_name + constants.BANG + "PyDictObject",layer_name=self.process_layer,offset=int(dict_ptr))
               # Get the actual dictionary from this object 
               class_dict = class_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
               #  Iterate through class members to find methods 
               for k1, v1 in class_dict.items():
                   v_address1 = f"0x{v1.vol.offset:x}"
                   vtype1 = self.get_value_type(v1)
                   #  Process methods (functions within classes) 
                   if vtype1=="function" or vtype=="classmethod":
                      # Process class methods similar to regular functions 
                      func_obj = v1.cast_to("PyFunctionObject")
                      code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
                      func_name_obj=func_obj.func_name_obj
                      func_globals_obj= func_obj.func_globals_obj
                      func_module_obj= func_obj.func_module_obj
                      func_qualname_obj= func_obj.func_qualname_obj
                      func_name_obj_type = self.get_value_type(func_name_obj)
                      func_module_obj_type = self.get_value_type(func_module_obj)
                      func_qualname_obj_type = self.get_value_type(func_qualname_obj)
                      func_globals_dict = func_globals_obj.cast_to("PyDictObject")
                      func_globals=func_globals_dict.get_dict(cur_depth=0, max_depth=100, visited=set())
                     
                      try:
                        loader=func_globals['__loader__']
                        if loader is not None:
                            loader_type=self.get_value_type(loader)
                            if loader_type=="SourceFileLoader":
                               loader_dict=loader.get_value().get_dict(cur_depth=0, max_depth=100, visited=set())
                               if 'path' in loader_dict:
                                   path_obj = loader_dict['path']
                                   file_name_value = path_obj.get_value()
                      except KeyError:
                 
                         file_name_value = "<unknown file>"
                      except Exception as e:
                  
                         print(f"Error getting file name: {e}")
                         file_name_value = "<error>"
                      
                      collected_data.append((int(task.pid), v_address1, func_name_obj.get_value(), func_module_obj.get_value(), file_name_value))
          
           collected_data.append((int(task.pid),  "---------------",  "---------------",  "---------------",  "---------------"))
           return collected_data
      except Exception as e:
         print(f"Error processing module  in sys.modules: {e}")
    
    
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
            # Calculate the address of the generation head (size =24 bytes

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
                   
                    # Move to the next object in the linked list"""
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
            # Return  Process ID,  function_address, function_name, module_name, file_name for each function 
            pid, add, func_name, module_name, file_name = item
            
            yield (0, (
                pid,
                add,
                f"{func_name:<20}",
                f"{module_name:<20}",
                f"{file_name:<20}"
            ))

    

    def run(self):
        # Calcualte the total runtime of the plugin
        overall_start_time = time.time()
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func
        )
        # Collect data from the tasks
        collected_data = self._collect_data(tasks)
        overall_end_time = time.time()
        total_time = overall_end_time - overall_start_time
        print(f"Total plugin execution time: {total_time:.4f} seconds")
     
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Func. Address", str),
                ("Func. Name", str),
                ("Module Name", str),
                ("                File Name", str)
              
            ],
            self._generator(collected_data)
        )
