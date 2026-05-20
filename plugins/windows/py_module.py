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

class Py_Module(interfaces.plugins.PluginInterface):
    """
    - This plugin extracts and analyzes Python modules from memory dumps.
    - It identifies the modules of the application, their package structure, initialization status, and file paths.
    - Particularly useful for identifying suspicious modules loaded by Python malware.

    Requirements:
    - Installed Volatility 3 Framework 
    - Windows Memory Dump with Python processes
    - Python 3.8 (support for other versions can be added by extending the python_modules list)

    Analysis workflow:
      1. Locate the _PyRuntime symbol in the memory dump.
      2. Access the garbage collector linked list.
      3. Find the root 'sys' module to access the sys.modules dictionary.
      4. Identify the main module as the entry point and expand to other modules in the application.
      5. For each module, call 'process_module' method to analyze the '__package__', '__loader__', '__spec__' attributes that provide more details about the module
    
   
     Usage:
      python3 vol.py -f "path/to/mem dump" windows.py_module.Py_Module  --pid=<process_id>
    
    Output:
    - PID: Process ID
    - Module Name: Name of the Python module
    - Package: The module's package hierarchy
    - Initializing: Whether the module is currently being imported (True/False)
    - Path: File path of the module
    
     Note: 
      All plugins  (py_class, py_module, py_func, py_code) share a common initial workflow:
        1. Locating the _PyRuntime address
        2. Traversing the garbage collector
        3. Finding key Python objects
      
      Where they differ is in their specialized analysis methods - this plugin specifically implements 
      the 'process_module' method to extract and analyze PyModuleObject structures, providing detailed
      information about module hierarchy, loading state, and file paths.
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
                description="Windows kernel",  # Changed to Windows kernel
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
          processes: Iterator of process objects to analyze
        
        Returns:
          list: Collected data as list of tuples (pid, generation, obj_type, obj_name, obj_address, obj_value)
        """
        
        python_table_name = python_Symbol_Table.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures"  # Changed to Windows filename
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
                module_obj1 = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyModuleObject",
                    layer_name=curr_layer.name,
                    offset=obj.vol.offset
                )
                
                # 1. Locate the 'modules'  field in the  root'sys' module
                # 2. Locate the main module within the 'modules' 
                module_name = module_obj1.get_name()
                module_dict1 = module_obj1.get_dict(cur_depth=0, max_depth=100, visited=set())
                if module_dict1:
                    
                    if 'modules' in module_dict1:
                       
                        sys_modules_obj = module_dict1['modules']
                        modules_name = sys_modules_obj.ob_type.dereference().get_name()
                        modules_type = sys_modules_obj.get_type(modules_name)
                        sys_modules_dict_obj = sys_modules_obj.cast_to("PyDictObject")
                        sys_modules_dict = sys_modules_dict_obj.get_dict(cur_depth=0, max_depth=100)
                        if sys_modules_dict:
                           
                            for modname, modobj in sys_modules_dict.items():
                              
                                if processed_main:
                                    break
                                mod_name = modobj.ob_type.dereference().get_name()
                                mod_type = modobj.get_type(mod_name)
                                
                                if mod_type == 'PyModuleObject':
                                    try:
                                        if modname == "__main__":
                                            modobj = modobj.cast_to("PyModuleObject")
                                            modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100)
                                            modcollected_data =self.process_module(modobj, python_table_name, process)
                                            collected_data.extend(modcollected_data)
                                            processed_main = True

                                    except Exception as e:
                                        print(f"Error processing module '{modname}' in sys.modules: {e}")
                                else:
                                    continue
        return collected_data
    
    
    def process_module(self, modobj, python_table_name, process):
      """
      Process a Python module to extract its metadata from all the classes.
    
      This method extracts key information about a module including:
      - Module name from '__name__ 'attribute
      - Package hierarchy from '__package__' attribute
      - File path from '__loader__'.'path' attribute
      - Initialization status from '__spec__'.'_initializing' attribute
    
      Args:
        modobj: PyModuleObject instance representing the module
        python_table_name: Name of the Python symbol table
        process: Process  object
        
      Returns:
        list: Collection of tuples containing module metadata
              (pid, module_name, package, initializing, path)
      
      Note: '__spec__' attribute is also a dictionary that contains information about the module, such as loader_state, '_initializing', and '_cached'
      """
      
      try:
        collected_data = []
        # Get the module's dictionary which contains all its attributes and objects  
        modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
        if modobj_dict:
           # Iterate through each object in the module's dictionary 
           for k, v in modobj_dict.items():
              # Get object's memory address as a hex string 
              v_address = f"0x{v.vol.offset:x}"
              # Determine the object type 
              vtype = self.get_value_type(v)
              v_name = v.ob_type.dereference().get_name()
              v_type2 = v.get_type(v_name)
              # Process module objects 
              if vtype=="module":
                 # Cast the object to a PyModuleObject to access its fields 
                 module_obj = v.cast_to("PyModuleObject")
                 # Get the module name 
                 module_name = module_obj.get_name()
                 # Get the module's dictionary containing all its attributes 
                 modobj_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                 # Get package information (shows hierarchy like 'package.subpackage') 
                 module_package= modobj_dict['__package__'].get_value() 
                 if module_package is None:
                    module_package="None"
                 #  Get loader information (contains path and loading mechanism) 
                 module_loader= modobj_dict['__loader__'].get_value()
                 module_loader_type = self.get_value_type(module_loader)
                 if module_loader_type=="dict":
                    module_loader=module_loader.get_dict()
                    # Extract the path from the loader if available 
                    loader_path = module_loader['path'].get_value() if 'path' in module_loader else 'Unknown'
                 else:
                    loader_path = 'None'
                 #  Get module spec (contains metadata about the module) 
                 module_spec= modobj_dict['__spec__'].get_value()
                 module_spec_type = self.get_value_type(module_spec)
                 if module_spec_type=="dict":
                    #  Extract key metadata from the spec 
                    module_spec=module_spec.get_dict()
                    spec_loader_state = module_spec['loader_state'].get_value() if 'loader_state' in module_spec else 'Unknown'
                    # _initializing shows if module is currently being imported
                    spec_loader_initializing= module_spec['_initializing'].get_value() if '_initializing' in module_spec else 'Unknown' 
                    # _set_fileattr indicates whether the module has a __file__ attribute 
                    spec_set_fileattr = module_spec['_set_fileattr'].get_value() if '_set_fileattr' in module_spec else 'Unknown'
                    #  _cached indicates the location of the module's .pyc file if applicable 
                    spec_cached = module_spec['_cached'].get_value() if '_cached' in module_spec else 'Unknown'
                    # Add module information to our results 
                 collected_data.append((int(process.UniqueProcessId), module_name, module_package, spec_loader_initializing,loader_path, ))  
            
              
              # Provide more comprehansive view by locating each class of the main module and process their modules as well
              if vtype=="type":
                 # Process class modules similar to regular modules 
                 type_casted = v.cast_to("PyTypeObject")
                 dict_ptr = type_casted.tp_dict
                 if not dict_ptr:
                    return None
                 class_obj = self.context.object(object_type=python_table_name + constants.BANG + "PyDictObject",layer_name=self.process_layer,offset=int(dict_ptr))
                 class_dict = class_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                 for k1, v1 in class_dict.items():
                  v_address1 = f"0x{v1.vol.offset:x}"
                  vtype1 = self.get_value_type(v1)
                  if vtype1=="module": 
                    module_obj = v.cast_to("PyModuleObject") 
                    modobj_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                    module_name= modobj_dict['__name__'].get_value()
                    module_package= modobj_dict['__package__'].get_value()
                    if module_package is None:
                       module_package="None"
                    module_loader= modobj_dict['__loader__'].get_value()
                    module_loader_type = self.get_value_type(module_loader)
                    if module_loader_type=="dict":
                       module_loader=module_loader.get_dict()
                       loader_path = module_loader['path'].get_value() if 'path' in module_loader else 'Unknown'
                    else:
                       loader_path = 'None'
                    module_spec= modobj_dict['__spec__'].get_value()
                    module_spec_type = self.get_value_type(module_spec)
                    if module_spec_type=="dict":
                       module_spec=module_spec.get_dict()
                       spec_loader_state = module_spec['loader_state'].get_value() if 'loader_state' in module_spec else 'Unknown'
                       spec_loader_initializing= module_spec['_initializing'].get_value() if '_initializing' in module_spec else 'Unknown' 
                       spec_set_fileattr = module_spec['_set_fileattr'].get_value() if '_set_fileattr' in module_spec else 'Unknown' 
                       spec_cached = module_spec['_cached'].get_value() if '_cached' in module_spec else 'Unknown'
                    collected_data.append((int(process.UniqueProcessId), module_name, module_package,  spec_loader_initializing,loader_path,))  
           collected_data.append((int(process.UniqueProcessId), "---------------", "---------------", "---------------","---------------", ))    
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
        This method  traverses all generations to find Python objects, locating the main module 'sys' 
        and accessing its 'modules' field that contains all the application classes.
        
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
                #  Create a PyObject at the current offset
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
                    
                    #  Count the objects per generation
                    gen_object_count += 1
                    
                    #  Locate the 'sys' module, once find it, breaks the loop
                    if type_name == 'module':
                       module_obj = obj.cast_to("PyModuleObject")
                       module_name = module_obj.get_name()
                       if module_name == 'sys':
                           objects.append((i, type_name, obj))
                           found_sys = True
                           break
                    
                    #  Move to the next object in the linked list
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
        #  Generate formatted output rows for the UI
        for item in data:    
            # Return  Process ID, module name,  parent package, module is currently being imported (True/False), and file path for each module
            pid,  module_name, pkg,initializing ,path= item 
            pkg_str = str(pkg) if pkg is not None else "None"
            path_str = str(path) if path is not None else "None"
            initializing_str = str(initializing) if initializing is not None else "None"
           

            yield (0, (
                pid,
                f"{module_name:<20}",
                f"{pkg_str:<10}",
                f"{initializing_str :<10}",
                path_str
                
            ))
    
    

    def run(self):
        #  Calcualte the total runtime of the plugin
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


      
        # Collect data from the processes
        collected_data = self._collect_data(processes)
        overall_end_time = time.time()
        total_time = overall_end_time - overall_start_time
        print(f"Total plugin execution time: {total_time:.4f} seconds")
    
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Module Name", str),
                ("    Package", str),
                ("Initializing", str),
                ("Path", str)
              
            ],
            self._generator(collected_data)
        )
