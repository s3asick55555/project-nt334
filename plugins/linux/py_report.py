from volatility3.framework import interfaces, renderers, constants
from volatility3.plugins.linux import pslist 
from volatility3.plugins.linux import elf_symbols # Plugin to locate _PyRuntime in the dynamic table in the ELF header
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.symbols.generic.types.python.python_symbol_table import python_Symbol_Table
import time
import json
import dis


class Py_Report(interfaces.plugins.PluginInterface):
    """
    Unified Python Process Analysis Plugin
    
    This plugin combines the functionality of py_class, py_module, py_function, and py_code
    to provide a complete analysis of Python processes with all results aggregated, ready to be analyzed by LLMs.
    
    - All classes with their attributes
    - All modules with packages and paths
    - All functions with signatures
    - All bytecode with disassembly
    """
    
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    
    @classmethod
    def get_requirements(cls):
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
            requirements.StringRequirement(
                name="report-path",
                description="Path to report",
                optional=True,
            ),
        ]
    
    # Shared functions

    def find_py_runtime_address(self, task):
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
        for i in range(GC_GENERATIONS):
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

        return objects

    def _collect_data(self, processes, object_type: str):
        
        python_table_name = python_Symbol_Table.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python_data_structures"  # Changed to Windows filename
        )

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
                                            if object_type == 'FUNCTION':
                                                modcollected_data = self.function_process_module(modobj, python_table_name, process)
                                            elif object_type == 'MODULE':
                                                modcollected_data = self.module_process_module(modobj, python_table_name, process)
                                            elif object_type == 'CODE':
                                                modcollected_data = self.code_process_module(modobj, python_table_name, process)
                                            else:
                                                modcollected_data = None
                                            collected_data.extend(modcollected_data)
                                            processed_main= True
                                else:
                                    continue
        return collected_data

# Py_Function
    def function_process_module(self, modobj, python_table_name, process):
      try:
        
        collected_data = []
        # Get the module's dictionary which contains all its objects 
        modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
        # print(modobj_dict)
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
               collected_data.append({"name": func_name_obj.get_value(), "module":func_module_obj.get_value(), "filename": file_name_value})
           
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
               # Get the actual dictionary from this object """
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
                      
                      collected_data.append({"name": func_name_obj.get_value(), "module":func_module_obj.get_value(), "filename": file_name_value})
          
           return collected_data
      except Exception as e:
         print(f"Error processing module  in sys.modules: {e}")

# Py_Module
    def module_process_module(self, modobj, python_table_name, process):
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
                    spec_loader_initializing= module_spec['_initializing'].get_value() if '_initializing' in module_spec else None 
                    # _set_fileattr indicates whether the module has a __file__ attribute 
                    spec_set_fileattr = module_spec['_set_fileattr'].get_value() if '_set_fileattr' in module_spec else 'Unknown'
                    #  _cached indicates the location of the module's .pyc file if applicable 
                    spec_cached = module_spec['_cached'].get_value() if '_cached' in module_spec else 'Unknown'
                    # Add module information to our results 
                 collected_data.append({"name": module_name, "package": module_package, "initializing": spec_loader_initializing, "path": loader_path})  
            
              
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
                       spec_loader_initializing= module_spec['_initializing'].get_value() if '_initializing' in module_spec else None 
                       spec_set_fileattr = module_spec['_set_fileattr'].get_value() if '_set_fileattr' in module_spec else 'Unknown' 
                       spec_cached = module_spec['_cached'].get_value() if '_cached' in module_spec else 'Unknown'
                    collected_data.append({"name": module_name, "package": module_package, "initializing": spec_loader_initializing, "path": loader_path})  
           return collected_data
      except Exception as e:
         print(f"Error processing module in sys.modules: {e}")

# Py_Code
    def code_process_module(self, modobj, python_table_name, process):
      try:
        collected_data = []
        # Get the module's dictionary which contains all its objects  
        modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
        if not modobj_dict:
            return collected_data
            
        #  Iterate through each object in the module's dictionary """
        for k, v in modobj_dict.items():
          try:
            vtype = self.get_value_type(v)
            
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
                      disassembled_code = "???"
                   
                   # Add code information to our results """
                   collected_data.append({
                       "name": code_obj_info.co_name if code_obj_info else "unknown", 
                       "args_count": code_obj_info.co_argcount if code_obj_info else 0, 
                       "locals_count": code_obj_info.co_nlocals if code_obj_info else 0, 
                       "var_names": code_obj_info.co_varnames if code_obj_info else (),
                       "code":disassembled_code
                   })
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
                          vtype1 = self.get_value_type(v1)
                          if vtype1=="function" or vtype1=="classmethod": 
                             func_obj = v1.cast_to("PyFunctionObject") 
                             code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
                             code_obj_info = code_obj.to_code_object()

                             if code_obj_info and hasattr(code_obj_info, 'co_code') and code_obj_info.co_code:
                                disassembled_code = self.disassemble_code_with_validation(code_obj_info)
                             else:
                                disassembled_code = "???"
                                
                             collected_data.append({
                                 "name": code_obj_info.co_name if code_obj_info else "unknown", 
                                 "args_count": code_obj_info.co_argcount if code_obj_info else 0, 
                                 "locals_count": code_obj_info.co_nlocals if code_obj_info else 0, 
                                 "var_names": code_obj_info.co_varnames if code_obj_info else (),
                                 "code": disassembled_code
                             })
                      except Exception as method_err:
                          print(f"Error processing class method '{k1}': {method_err}")
                          continue
               except Exception as class_err:
                   print(f"Error processing class '{k}': {class_err}")
                   continue
          except Exception as item_err:
              print(f"Error processing module item '{k}': {item_err}")
              continue
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

                instructions.append({"offset": instr.offset, "opname": opname, "argval":argval})

            except Exception as e:
                print(f"Error processing instruction: {str(e)[:50]}")
                continue
      except Exception as disasm_err:
          return f"<disassembly failed: {str(disasm_err)[:50]}>"
      
      if not instructions:
          return "<no bytecode instructions found>"
      
      return instructions
      
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

# Py_Class
    def traverse_GC_class(self, context, curr_layer, PyRuntime, PyGC_Head_Offset, python_table_name):
        objects = []
        GC_GENERATIONS = 3
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
        
        # Locate 'sys' module and then the '__main__' module in its modules field
        for (i, _, mod_obj) in modules:
            module_obj = mod_obj.cast_to("PyModuleObject")
            module_name = module_obj.get_name()
            if module_name == 'sys':
                sys_dict = module_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                if sys_dict and 'modules' in sys_dict: 
                    sys_modules_obj = sys_dict['modules']
                    sys_modules_dict_obj = sys_modules_obj.cast_to("PyDictObject")
                    sys_modules_dict = sys_modules_dict_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
                    if sys_modules_dict:
                        for modname, modobj in sys_modules_dict.items():
                            mod_name = modobj.ob_type.dereference().get_name()
                            mod_type = modobj.get_type(mod_name)
                            if mod_type == 'PyModuleObject' and modname == "__main__": 
                                objects.append((i, mod_name, modobj))
                                modobj = modobj.cast_to("PyModuleObject")
                                """Access the dictionary associated with the module that contains its objects."""
                                modobj_dict = modobj.get_dict(cur_depth=0, max_depth=100, visited=set())
                                if modobj_dict:
                                    for k, v in modobj_dict.items():
                                        vtype = self.get_value_type(v)
                                        if vtype=="type":
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

    def _collect_data_class(self, processes):
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
        objects = self.traverse_GC_class(self.context, curr_layer, PyRuntime, PYGC_HEAD_OFFSET, python_table_name)
       
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
           
            # Get all the class isntances that are represented as PyDictObject
            else:  
  
                   try:
                        value=self.process_object_recursively(obj)
                        collected_data.append({"Obj_Type": obj_type, "Obj_Name": None, "Obj_Value": value})
                         
                   except Exception as e:
                      print(f"Error reading instance at {hex(obj.vol.offset)}: {e}")
           
        return collected_data

    def recursive_process(self,obj_dict,generation,process,python_table_name,collected_data):        
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
                       collected_data.append({"Obj_Type": vtype, "Obj_Name":k, "Obj_Value": vv})
        for t in types:
           #Each  class is represented by the 'PyTypeObject' data structure that contains the class attributes and objects located in tis  'tp_dict' dictionary 
           type_casted = t.cast_to("PyTypeObject")
           dict_ptr = type_casted.tp_dict
           if not dict_ptr:
              return None
           
           class_obj = self.context.object(object_type=python_table_name + constants.BANG + "PyDictObject",layer_name=self.process_layer,offset=int(dict_ptr))
           class_dict = class_obj.get_dict(cur_depth=0, max_depth=100, visited=set())
           self.recursive_process(class_dict,generation,process,python_table_name,collected_data)
                       
        return collected_data
    
    def process_object_recursively(self, obj):
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

    def _collect_all_data(self, processes):
        """Aggregate results from all 4 plugins: py_class, py_module, py_function, py_code"""
        collected_data = []
        
        try:            
            process_list = list(processes)
            try:
                class_data = self._collect_data_class(iter(process_list))
                if class_data:
                    for item in class_data:
                        collected_data.append({"CLASS": item})
            except Exception as e:
                print(f"[!] Error collecting class data: {e}")
            try:
                module_data = self._collect_data(iter(process_list), "MODULE")
                if module_data:
                    for item in module_data:
                        collected_data.append({"MODULE": item})
            except Exception as e:
                print(f"[!] Error collecting module data: {e}")
            try:
                function_data = self._collect_data(iter(process_list), "FUNCTION")
                if function_data:
                    for item in function_data:
                        collected_data.append({"FUNCTION":item})
            except Exception as e:
                print(f"[!] Error collecting function data: {e}")
            try:
                code_data = self._collect_data(iter(process_list), "CODE")
                if code_data:
                    for item in code_data:
                        collected_data.append({"CODE": item})
            except Exception as e:
                print(f"[!] Error collecting code data: {e}")
        
        except Exception as e:
            print(f"[!] Error initializing plugins: {e}")
        
        return collected_data
    
    def _process_data(self, collected_data, pid):       
        # Separate data by type
        classes = []
        modules = []
        functions = []
        code_objects = []
        
        for item in collected_data:
            obj_type = list(item.keys())[0]
            obj_data = item[obj_type]
            
            if obj_type == "CLASS":
                classes.append(obj_data)
            elif obj_type == "MODULE":
                modules.append(obj_data)
            elif obj_type == "FUNCTION":
                functions.append(obj_data)
            elif obj_type == "CODE":
                code_objects.append(obj_data)
        
        # Build structured output
        output = {
            "metadata": {
                "process": pid,
                "summary": {
                    "total_classes": len(classes),
                    "total_modules": len(modules),
                    "total_functions": len(functions),
                    "total_code_objects": len(code_objects),
                    "total_objects": len(collected_data)
                }
            },
            "classes": classes,
            "modules": modules,
            "functions": functions,
            "code_objects": code_objects
        }
        
        return output
    
    def _generator(self, summary_data):
        """Generate output rows for summary counts"""
        for obj_type, count in summary_data.items():
            yield (0, (obj_type, str(count)))
    
    def run(self):
        """Main plugin execution - aggregate and count results from 4 plugins"""
        overall_start_time = time.time()
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        processes = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func
        )
        
        # Collect all data from all plugins
        collected_data = self._collect_all_data(processes)
        overall_end_time = time.time()
        total_time = overall_end_time - overall_start_time
        
        # Count by type
        class_count = len([x for x in collected_data if list(x.keys())[0] == 'CLASS'])
        module_count = len([x for x in collected_data if list(x.keys())[0] == 'MODULE'])
        function_count = len([x for x in collected_data if list(x.keys())[0] == 'FUNCTION'])
        code_count = len([x for x in collected_data if list(x.keys())[0] == 'CODE'])
        
        # Generate LLM-friendly JSON output
        pid = self.config.get("pid", None)
        processed_data = self._process_data(collected_data, pid)
        print(processed_data)
        
        # Save to report file if specified
        report_path = self.config.get("report-path", None)
        if report_path != None:
            with open(report_path, "w") as f:
                json.dump(processed_data, f)
        
        summary = {
            "Classes": class_count,
            "Modules": module_count,
            "Functions": function_count,
            "Code Objects": code_count,
            "Total Objects": len(collected_data),
        }
        
        print(f"Classes Found: {class_count}")
        print(f"Modules Found: {module_count}")
        print(f"Functions Found: {function_count}")
        print(f"Code Objects Found: {code_count}")
        print(f"Total Objects: {len(collected_data)}")
        print(f"Analysis Time: {total_time:.4f} seconds")
        
        return renderers.TreeGrid(
            [
                ("Object Type", str),
                ("Count", str),
            ],
            self._generator(summary)
        )
