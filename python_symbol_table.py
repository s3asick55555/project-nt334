from volatility3.framework.symbols import intermed
from volatility3.framework import objects, constants
from volatility3.framework import exceptions
import struct
import types
import collections
import marshal
import textwrap
import dis # Used for disassembling Python bytecode
import sys
from io import StringIO #creates an in-memory file-like object for reading and writing text without using a physical file
import io

"""
- This file represent  the cornerstone of our plugins (Py_Class, Py_Module, Py_Function, Py_Code, Py_Stack_Call, and Py_Stack_Var)
- It defines the memory structures of CPython's runtime objects for forensic analysis.
- It maps Python's internal C structures to Volatility 3 classes for memory dump interpretation.
- It works with both Linux and Windows memory dumps

The analysis approach consists of:
  1. Creating an intermediate symbol table for Python objects
  2. Locating and handles complex memory layouts,  including  Python's garbage collector linked list anf function call stacks
  3. Implementing memory parsing logic for all Python types (strings, dicts, lists, etc.)
  4. Providing recursive value extraction with cycle detection
  5. Analyzing attributes, values, and relationships between objects
  6. Providing stack frame and execution state reconstruction
"""

class python_Symbol_Table(intermed.IntermediateSymbolTable):
    """
    This class extends the IntermediateSymbolTable of Volatility3 to create custom Python object types
    for parsing Python objects in memory. 
    
    It maps Volatility object types to Python runtime
    structures, allowing for deep inspection of Python applications in memory dumps.
    
    The symbol table is created from a JSON file (python_data_structures.json) containing
    the data structures generated using dwarf2json. 
    This file must define all data structures used by the Python interpreter.
    
    Usage:
        python_table_name = Python_Objects_Process.create(
            context, config_path, sub_path="generic/types/python", 
            filename="python_data_structures"
        )

    """
    
    def __init__(self, *args, **kwargs):
        """
        Initialize the symbol table with Python object type definitions.
    
        Maps each Python data structure to its corresponding Volatility class implementation.
        The mapping covers all core Python object types, from basic types like integers and strings
        to complex structures like modules, functions, and frames.
    
        These class mappings enable the reconstruction of Python objects from their raw memory
        representation, preserving their type-specific behaviors and attributes.
    
        For more information about these types, see the CPython documentation:
        https://github.com/python/cpython/tree/main/Include/cpython
    
        Note: Different Python versions may have slightly different memory layouts.
        The plugins attempt to handle these differences, but version-specific adaptations
        may be necessary for complete analysis.
        """
        
        super().__init__(*args, **kwargs)
    
        self.set_type_class("PyGC_Head", PyGC_Head) 
        self.set_type_class("PyObject", PyObject)
        self.set_type_class("PyTypeObject", PyTypeObject)
        self.set_type_class("PyDictObject", PyDictObject)
        self.set_type_class("PyDictKeysObject", PyDictKeysObject)
        self.set_type_class("PyDictKeyEntry", PyDictKeyEntry)
        self.set_type_class("PyASCIIObject", PyASCIIObject)
        self.set_type_class("PyBoolObject", PyBoolObject)
        self.set_type_class("PyLongObject", PyLongObject)
        self.set_type_class("PyTupleObject", PyTupleObject)
        self.set_type_class("PyListObject", PyListObject)
        self.set_type_class("PySetObject", PySetObject)
        self.set_type_class("PyWeakReference", PyWeakReference)
        self.set_type_class("PyBytesObject", PyBytesObject)
        self.set_type_class("PyFloatObject", PyFloatObject)
        self.set_type_class("PyModuleObject", PyModuleObject)
        self.set_type_class("PyFunctionObject", PyFunctionObject) 
        self.set_type_class("PyCFunctionObject", PyCFunctionObject)
        self.set_type_class("PyWrapperDescrObject", PyWrapperDescrObject)
        self.set_type_class("PyMethodDef", PyMethodDef)
        self.set_type_class("PyMemberDef", PyMemberDef)
        self.set_type_class("PyGetSetDef", PyGetSetDef)
        self.set_type_class("PyMethodDescrObject", PyMethodDescrObject)
        self.set_type_class("PyGetSetDescrObject", PyGetSetDescrObject)
        self.set_type_class("PyMemberDescrObject", PyMemberDescrObject)
        self.set_type_class("PyCodeObject", PyCodeObject)
        self.set_type_class("_ODictNode", _ODictNode)
        self.set_type_class("PyDescrObject", PyDescrObject)
        self.set_type_class("wrapperobject", wrapperobject)
        self.set_type_class("PyODictObject", PyODictObject)
        self.set_type_class("PyCellObject", PyCellObject)
        self.set_type_class("classmethod", classmethod)
        self.set_type_class("PyByteArrayObject", PyByteArrayObject)
        self.set_type_class("PyCapsule", PyCapsule)
        self.set_type_class("PyComplexObject", PyComplexObject)
        self.set_type_class("enumobject", enumobject) 
        self.set_type_class("seqiterobject", seqiterobject)
        self.set_type_class("calliterobject", calliterobject)
        self.set_type_class("PyMethodObject", PyMethodObject)
        self.set_type_class("_PyNamespaceObject", _PyNamespaceObject)
        self.set_type_class("PyPickleBufferObject", PyPickleBufferObject)
        self.set_type_class("rangeobject", rangeobject)
        self.set_type_class("PySliceObject", PySliceObject)
        self.set_type_class("PyInstanceObject", PyInstanceObject)
        self.set_type_class("PyInterpreterState", PyInterpreterState)
        self.set_type_class("PyThreadState", PyThreadState)
        self.set_type_class("PyFrameObject", PyFrameObject)
        self.set_type_class("PyModuleDef", PyModuleDef)
        self.set_type_class("staticmethod", staticmethod) 
        self.set_type_class("classmethod", classmethod)



# -------------------------------------------------------------------------
# Garbage Collection and Runtime Structures
# -------------------------------------------------------------------------
# These classes represent the foundation of Python's memory management system.
# The garbage collector uses a generational approach with circular doubly-linked
# lists to track all Python objects. These structures are critical for locating
# Python objects in memory dumps.



class PyGC_Head(objects.StructType):
     """
     Garbage collector head structure.
     This structure forms the circular doubly-linked list that makes up
     the Python garbage collector system. Each PyGC_Head precedes a Python
     object in memory.
     """
     
     def get_next(self):
        """
        Get the offset of the next object in the GC chain.
        
        Returns:
            int: Memory offset of the next object in the GC list
        """
        
        return int.from_bytes(self._context.layers[self.vol.layer_name].read(self.vol.offset, 8), byteorder='little')
     
     def get_prev(self):
      
        """
        Get the offset of the previous object in the GC chain.
        
        Returns:
            int: Memory offset of the previous object in the GC list
        """
        return int.from_bytes(self._context.layers[self.vol.layer_name].read(self.vol.offset + 8, 8), byteorder='little')

class PyInterpreterState(objects.StructType):
    
    """
    Python interpreter state object.
    
    This structure represents the global state of a Python interpreter instance.
    
    Note: Python's runtime can have multiple interpreter instances. 
    The _PyRuntime structure can manage multiple interpreters through its interpreter state list, allowing Python to support multiple isolated execution 
    environments within the same process.
    """
    
    @property
    def next(self):
        """Get the next interpreter state"""
        
        return self.member('next')

    @property
    def tstate_head(self):
        """Get the head of thread state chain for this interpreter."""
        return self.member('tstate_head')

class PyFrameObject(objects.StructType):
    """
    Python frame object.
    
    Frame objects represent the execution state of a Python function call.
    Each frame contains local and global variables, code object references,
    and links to other frames in the call stack.
    """

    @property
    def f_back(self):
        """Pointer to the previous (calling) frame in the call stack."""
        return self.member('f_back')

    @property
    def f_code(self):
        """Pointer to the PyCodeObject representing the executed code."""
        return self.member('f_code')

    @property
    def f_lineno(self):
        """Integer line number of the current execution point in this frame."""
        return self.member('f_lineno')

    @property
    def f_globals(self):
        """Pointer to the dictionary of globals."""
        return self.member("f_globals")

    @property
    def f_locals(self):
        """Pointer to a dictionary or None."""
        return self.member("f_locals")
        
    @property
    def f_globals_dict(self):
        """
        Get the globals dictionary for this frame.
        
        Returns:
            dict: The dictionary of global variables or None if not available
        """
        
        ptr = int(self.f_globals)
        if ptr == 0:
            return None
        try:
            dict_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyDictObject",
                layer_name=self.vol.layer_name,
                offset=ptr
            )
            return dict_obj.get_dict(cur_depth=0, max_depth=5, visited=set())
        except Exception as e:
            print(f"Error reading f_globals dict at {hex(ptr)}: {e}")
            return None

    
    @property
    def f_locals_obj(self):
        """
        Get the locals dictionary for this frame.
        
        Returns:
            dict: The dictionary of local variables or None if not available
        """
        
        ptr = int(self.f_locals)
        if ptr == 0:
            return None
        try:
            dict_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyDictObject",
                layer_name=self.vol.layer_name,
                offset=ptr
            )
            return dict_obj.get_dict(cur_depth=0, max_depth=5, visited=set())
        except Exception as e:
            print(f"Error reading f_locals as dict at {hex(ptr)}: {e}")
            return None
    
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """
        Get a human-readable representation of this frame.
        
        Args:
            cur_depth: Current recursion depth
            max_depth: Maximum recursion depth
            visited: Set of visited object addresses to prevent cycles
            
        Returns:
            str: Human-readable representation of the frame
        This fucntion lcoates the code object associated with the frame and access its informations 
        (e.g., filename, start line number of the code within the file)
        """
        lineno = int(self.f_lineno)
        code_obj = self.f_code.dereference() if self.f_code else None
        function_name = "<unknown>"
        filename = "<unknown>"
        if code_obj:
            try:
                co_name_obj = code_obj.co_name.dereference()
                co_filename_obj = code_obj.co_filename.dereference()
                function_name = co_name_obj.get_value() or "<unknown>"
                filename = co_filename_obj.get_value() or "<unknown>"
            except Exception:
                pass
        
        return f"<PyFrameObject at 0x{self.vol.offset:x} {filename}:{function_name}:{lineno}>"


class PyThreadState(objects.StructType):
    """
    Python thread state structure.
    
    Represents the state of a Python thread, including its frame stack, id, and pointers to the next and previous threads.
    """
    
    @property
    def prev(self):
        return self.member('prev')

    @property
    def next(self):
        return self.member('next')

    @property
    def frame(self):
        """Returns the head of this thread's stack frames (PyFrameObject)."""
        return self.member('frame')
    @property
    def get_id(self):
        
        return self.member('thread_id')
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """return the address of the found thread"""
        return f"<PyThreadState at 0x{self.vol.offset:x}>"
        


# -------------------------------------------------------------------------
# Base Object Structure
# -------------------------------------------------------------------------
# PyObject is the foundation of all Python objects in memory.
# All Python objects begin with this structure containing type information
# and reference counting. The get_value method serves as the main
# recursive method for extracting values from memory.

class PyObject(objects.StructType): 
    def get_type(self, name):
        """
        Map a Python type name to its corresponding structure name.
        
        Args:
            name: Python type name as a string
            
        Returns:
            str: Corresponding structure name or None if not found
        """
        types = {
             'NoneType': 'None','str': 'PyASCIIObject', 'int': 'PyLongObject', 'method_descriptor': 'PyMethodDescrObject',
            'bool': 'PyBoolObject', 'tuple': 'PyTupleObject', 'list': 'PyListObject','wrapper_descriptor': 'PyWrapperDescrObject',  'method-wrapper': 'wrapperobject',
            'set': 'PySetObject', 'frozenset': 'PySetObject', 'function': 'PyFunctionObject', 'methoddef':'PyMethodDef','member_descriptor': 'PyMemberDescrObject',
            'code': 'PyCodeObject', 'bytes': 'PyBytesObject', 'Parameter': None,'builtin_function_or_method':'PyCFunctionObject',
            'dict': 'PyDictObject', 'float': 'PyFloatObject','getset_descriptor': 'PyGetSetDescrObject','staticmethod':'staticmethod', 
            'module': 'PyModuleObject', 'type': 'PyTypeObject', 'weakref':'PyWeakReference',  'OrderedDict': 'PyODictObject',
             'collections.OrderedDict': 'PyODictObject',  'cell': 'PyCellObject', 'classmethod': 'classmethod','bytearray': 'PyByteArrayObject',
        'complex': 'PyComplexObject','enumerate': 'enumobject','frame': 'PyFrameObject', 'range': 'rangeobject','slice': 'PySliceObject', 'method': 'PyMethodObject', 'capsule':'PyCapsule', }
        mapped_type = types.get(name)
       
        return mapped_type
   
   
    @property
    def ob_type(self):
        """Get the type object for this object."""
        return self.member('ob_type')
    
    
    def get_value_type(self, value):
        """
        Get the type name of a value.
        
        Args:
            value: A Python object value
            
        Returns:
            str: Type name of the value or None on error
        """
        
        
        if value is None:
            return 'NoneType'
        if hasattr(value, 'ob_type'):
            try:
                ob_type = value.ob_type.dereference()
                tp_name_ptr = ob_type.tp_name
                type_name = self.read_cstring(tp_name_ptr)
                return type_name.split('.')[-1]  # Get the base type name
            except Exception as e:
                print(f"Error getting type name of PyObject: {str(e)}")
                return None
        else:
            # For primitive types, use type()
            return type(value).__name__
    
    def read_cstring(self, addr, max_length=256):
        """
        Read a null-terminated C string from memory.
        
        Args:
            addr: Memory address to read from
            max_length: Maximum bytes to read
            
        Returns:
            str: The string read from memory
        """
        
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring
    
    
    
    def cast_to(self, type_name):
        
        """
        Cast this object to a specific Python type.
        
        Args:
            type_name: Name of the type to cast to
            
        Returns:
            The object cast to the specified type
        """
        if constants.BANG in type_name:
            object_type = type_name
        else:
            symbol_table_name = self.get_symbol_table_name()
            object_type = symbol_table_name + constants.BANG + type_name
        return self._context.object(
            object_type=object_type,
            layer_name=self.vol.layer_name,
            offset=self.vol.offset,
        )
     
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """
        Retrieves the object's value according to it's type.
        
        This is a deep recursive method that handles all Python types
        and properly manages recursion depth to prevent stack overflows and detect reference cycles in the case of LARGE dictionaries
        
        
        Args:
            cur_depth: Current recursion depth
            max_depth: Maximum recursion depth
            visited: Set of visited object addresses to prevent cycles
            
        Returns:
            The Python value represented by this object
        """
        
        
        
        obj_type_name = self.get_type_name()
        track_for_cycles = obj_type_name not in {'int', 'bool', 'float', 'str', 'bytes', 'cell','NoneType', 'ellipsis'}

        if track_for_cycles:
            if visited is None:
               visited = set()
 
            obj_id = int(self.vol.offset)

            if obj_id in visited:
                return f"{obj_type_name}"
            visited.add(obj_id)
            # Limit recursion depth
            if max_depth is not None and cur_depth >= max_depth:
               return f"<{self.get_type_name()} object (max recursion depth reached)>"
        
        type = self.get_type(obj_type_name)
        
        
        
        if type is None:
          """  
          - For objects that are not defined in the  predefined type mapping dictionary 'types' above, we inspect the type's internal structure 
            (tp_dictoffset, tp_flags, etc.) to determine if the object has a dictionary and whether it's a heap-allocated type. 
          - For objects with a dictionary, we calculate the dictionary's address based on Python's memory layout rules and attempts to retrieve it. 
          - For objects without dictionaries or with invalid pointers, we provide appropriate fallback representations such as 'CPython Extension' 
            or '<built-in object>. 
          
          """
          
          tp_type = self.ob_type.dereference()
          tp_dictoffset = tp_type.tp_dictoffset
          tp_flags = int(tp_type.tp_flags)
          tp_basicsize = int(tp_type.tp_basicsize)
          tp_itemsize = int(tp_type.tp_itemsize)
          PY_TPFLAGS_HEAPTYPE = (1 << 9)  
          is_heap_type = bool(tp_flags & PY_TPFLAGS_HEAPTYPE)
          obj_type_name = tp_type.get_name()
          if tp_dictoffset != 0:
             if tp_dictoffset >= 0:
                dict_ptr_addr = self.vol.offset + tp_dictoffset
             else:
               instance_size = tp_basicsize
               if tp_itemsize > 0 and hasattr(self, 'ob_size'):
                instance_size += (self.ob_size * tp_itemsize)
               dict_ptr_addr = self.vol.offset + instance_size + tp_dictoffset

             curr_layer = self._context.layers[self.vol.layer_name]
             try:
              dict_addr_bytes = curr_layer.read(dict_ptr_addr, 8)
              dict_addr = int.from_bytes(dict_addr_bytes, byteorder='little', signed=False)

              if dict_addr and curr_layer.is_valid(dict_addr, 8):
                dict_obj = self._context.object(
                    object_type=self.get_symbol_table_name() + constants.BANG + "PyDictObject",
                    layer_name=self.vol.layer_name,
                    offset=dict_addr
                )
       
                return dict_obj
              else:
                # If the pointer is invalid or zero
                if is_heap_type:
                    return f"<Custom type at {hex(self.vol.offset)}>"
                else:
                    return f"CPython Extension"
             except Exception as e:
             
               return f"CPython Extension"
          else:
             if is_heap_type:
                return f"CPython Extension"
             else:
                return f"<{obj_type_name} built-in or extension object at {hex(self.vol.offset)} (no __dict__)>"
        
        elif type == 'PyDictObject':
              dict_obj = self.cast_to(type)
              return dict_obj.get_dict(cur_depth + 1, max_depth, visited) # Call the get_dict from the 'PyDictObject' class
        elif type == 'PyModuleObject':
              module_obj = self.cast_to(type) # Call the get_dict from the 'PyModuleObject' class
              return module_obj.get_dict(cur_depth + 1, max_depth, visited)
        elif type == 'PyFunctionObject':
            func_obj = self.cast_to("PyFunctionObject")
            func_addr = self.vol.offset
            code_obj = func_obj.func_code_obj.cast_to('PyCodeObject') # Get the bytecode of the function and disassemply it
         
            try:
            
              disassembled_code = self.disassemble_bytecode(code_obj) # Call disassemble_bytecode with the function code
              bytecode = code_obj.to_code_object()
             
            except Exception as e:
              print(f"Error decompiling code object at {hex(code_obj.vol.offset)}: {e}")
            return f"disassembled_code:  {disassembled_code}"
        
        elif type == 'PyCodeObject':
          
            code_obj = self.cast_to(type)
            disassembled_code = self.disassemble_bytecode(code_obj)
            return disassembled_code 

           
        elif type == 'None': #Handle None object
          return None
        elif type == 'Ellipsis': # Handle Python's Ellipsis object which is a singleton, so when we find it in memory, we return Python's built-in Ellipsis constant
          return Ellipsis
        else:
         obj = self.cast_to(type)
         value = obj.get_value(cur_depth + 1, max_depth, visited)
        if track_for_cycles:
         visited.remove(obj_id)
        return value
    
    
   
    
    
    def disassemble_bytecode(self, code_obj):
      """
      Disassemble a PyCodeObject's bytecode into human-readable instructions.
      
      Args:
          code_obj: A PyCodeObject to disassemble
          
      Returns:
          str: Disassembled bytecode as string or None on error
      """
      
      try:
        code = code_obj.to_code_object()
        if code and hasattr(code, 'co_code') and code.co_code:
            output = io.StringIO()
            disassembled_code = self.disassemble_code_with_validation(code)
            return disassembled_code
        else:
            print(f"Failed to reconstruct code object at {hex(code_obj.vol.offset)}")
            return None
      except Exception as e:
        print(f"Exception during disassembly of code object at {hex(code_obj.vol.offset)}: {str(e)}")
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
        const_obj_name=const_obj.ob_type.dereference().get_name()
        const_type=const_obj.get_type(const_obj_name)
        if const_type =="PyTupleObject":
           if hasattr(const_obj, 'get_value'):
                    tuple_items = const_obj.get_value()
                    if isinstance(tuple_items, (list, tuple)):
                        return tuple(resolve_pyobject(item) for item in tuple_items)
                    else:
                        raise ValueError("Unexpected value type in PyTupleObject")
       # print(f"const_type: {const_type}")
        if hasattr(const_obj, 'get_value'):
            return const_obj.get_value()
        return str(const_obj)

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
                if instr.arg < len(code.co_consts):
                    const_obj = code.co_consts[instr.arg]
                   
                    argval = resolve_pyobject(const_obj)
                else:
                    argval = f'<invalid const index {instr.arg}>'
            elif instr.opname in dis.hasname:
                if isinstance(code.co_names, tuple) and arg < len(code.co_names):
                    argval = code.co_names[arg]
                else:
                    argval = f'<invalid name index {arg}>'

            instructions.append(f"{instr.offset}: {opname} {argval}")
        except Exception as e:
            print(f"Error processing instruction 111at offset {instr.offset}: {str(e)}")
            continue

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
    
    def get_type_name(self):
        """
        Get the type name of this object.
        
        Returns:
            str: Type name as a string
        """
        return self.ob_type.dereference().get_name()
    
    
        
class classmethod(PyObject):
    """
    Python classmethod object.
    
    Represents a classmethod decorator applied to a method.
    Note: all the mentioned members have same field names of  the classmethod data structure
    """
    
    @property
    def cm_callable(self):
        return self.member('cm_callable') # the callable object is function

    @property
    def cm_dict(self):
        return self.member('cm_dict')
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            callable_obj = self.cm_callable.dereference()
            callable_value = callable_obj.get_value(cur_depth + 1, max_depth, visited)
            return f"<classmethod wrapping {callable_value}>"
        except Exception as e:
            return f"<classmethod at 0x{self.vol.offset:x} (error: {str(e)})>"
      


class staticmethod(PyObject):
    
    """
    Python staticmethod object.
    
    Represents a staticmethod decorator applied to a method.
    """
    @property
    def sm_callable(self):
        return self.member('sm_callable')# the callable object is function 
    @property
    def sm_dict(self):
        return self.member('sm_dict')
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            callable_obj = self.sm_callable.dereference()
            callable_value = callable_obj.get_value(cur_depth + 1, max_depth, visited)
            return f"<staticmethod wrapping {callable_value}>"
        except Exception as e:
            return f"<staticmethod at 0x{self.vol.offset:x} (error: {str(e)})>"
        

        
class PyInstanceObject(PyObject):
    
    """
    Python instance object (old-style in Python 2.x, maintains compatibility).
    
    Represents an instance of a class in memory.
    """
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        
        """
        Get the value of a Python instance.
        
        This method accesses the object's dictionary by:
        1. Determining the dictionary offset from the type object. We use tp_dictoffset because Python stores instance
           attributes in a dictionary whose location is determined by this offset from the
           object's base address. This follows CPython's own attribute lookup mechanism.
        2. Handling both positive and negative offsets (the latter for variable-sized objects). A negative offset requires 
           calculating from the end of the object, which happens with variable-sized objects 
           where the dictionary must be placed after the variable portion. 
        3. Variable-Size Handling: For variable-sized objects (those with tp_itemsize > 0),
           we must account for the actual size of the instance by adding the object's 
           size (ob_size) multiplied by the item size to find where the dictionary is stored.
        4. Retrieving the dictionary's contents if valid
        5. Providing fallback representations for objects without dictionaries
          
        
        Args:
            cur_depth: Current recursion depth
            max_depth: Maximum recursion depth
            visited: Set of visited object addresses to prevent cycles
            
        Returns:
            The instance value, typically a dictionary of attributes
        """
        obj_type_name = self.get_type_name()

        if visited is None:
            visited = set()

        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return f"<{obj_type_name} object (cycle detected)>"
        visited.add(obj_id)

        # Limit recursion depth
        if max_depth is not None and cur_depth >= max_depth:
            visited.remove(obj_id)
            return f"<{obj_type_name} object (max recursion depth reached)>"

        tp_type = self.ob_type.dereference()
        tp_dictoffset = tp_type.tp_dictoffset
         
        if tp_dictoffset != 0:
            if tp_dictoffset >= 0:
                dict_ptr_addr = self.vol.offset + tp_dictoffset
            else:
                # Handle negative tp_dictoffset
                tp_basicsize = tp_type.tp_basicsize
                tp_itemsize = tp_type.tp_itemsize
                # Calculate the instance size
                instance_size = tp_basicsize
                if tp_itemsize > 0 and hasattr(self, 'ob_size'):
                    # For variable-sized objects, include the size of variable part
                    instance_size += self.ob_size * tp_itemsize
                dict_ptr_addr = self.vol.offset + instance_size + tp_dictoffset

            curr_layer = self._context.layers[self.vol.layer_name]
            try:
                dict_addr_bytes = curr_layer.read(dict_ptr_addr, 8)
                dict_addr = int.from_bytes(dict_addr_bytes, byteorder='little')
                if dict_addr and curr_layer.is_valid(dict_addr, 8):
                    dict_obj = self._context.object(
                        object_type=self.get_symbol_table_name() + constants.BANG + "PyDictObject",
                        layer_name=self.vol.layer_name,
                        offset=dict_addr
                    )
                    value = dict_obj.get_dict(cur_depth + 1, max_depth, visited)
                else:
                    value = f"<{obj_type_name} PyInstanceObject at {hex(self.vol.offset)} (no __dict__)>"
            except Exception as e:
                print(f"Exception accessing __dict__ for {obj_type_name} object at {hex(self.vol.offset)}: {str(e)}")
                value = f"<{obj_type_name} object at {hex(self.vol.offset)} (unreadable __dict__)>"
        else:
            value = f"<{obj_type_name} PyInstanceObject at {hex(self.vol.offset)} (no __dict__)>"

        visited.remove(obj_id)
        return value


class PyBytesObject(PyObject):
    """
    Python bytes object.
    
    Represents an immutable sequence of bytes.
    """
    
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        
        """
        Get the raw bytes value.
        
        Args:
            cur_depth: Current recursion depth
            max_depth: Maximum recursion depth
            visited: Set of visited object addresses to prevent cycles
            
        Returns:
            bytes: The raw bytes data
        """
        
        try:
            # Get the current memory layer
            curr_layer = self._context.layers[self.vol.layer_name]
            
            # Get the size of the bytes object
            ob_size = self.ob_size
            
            """
              Calculate the correct data offset
              The bytes data starts after the PyBytesObject structure (40 bytes)
              and we need to adjust by 8 bytes to get the full content
            """
            base_offset = self.vol.offset + self.vol.size - 8
            
         
            
            try:
                # Read the byte data
                byte_data = curr_layer.read(base_offset, ob_size, pad=False)
                return byte_data
                
            except Exception as e:
                print(f"Error reading byte data at {hex(base_offset)}: {str(e)}")
                return b''
                
        except Exception as e:
            print(f"Error processing PyBytesObject at {hex(self.vol.offset)}: {str(e)}")
            return b''

   

class PyTypeObject(PyObject):
    """
    Python type object.
    
    Represents a Python type, which can be a class or a built-in type.
    Contains metadata about the type including methods, attributes, etc.

    """
    def get_name(self):
        """
        Get the name of this type.
        
        Returns:
            str: The type name
        """
        curr_layer = self._context.layers[self.vol.layer_name]
        tp_name_addr = self.tp_name
        type_name = self.read_cstring(tp_name_addr)
        return type_name
    
    
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """
        Get a string representation of this type.
        
        Args:
            cur_depth: Current recursion depth
            max_depth: Maximum recursion depth
            visited: Set of visited object addresses to prevent cycles
            
        Returns:
            str: String representation of the type
        """
        return f"<type '{self.get_name()}'>"
    
    def get_dict(self):
        """
        Get the dictionary of this type.
        
        Returns:
            dict: The type's dictionary containing methods and attributes

        Note: classes (the blueprint, not the instance) are just PyTypeObjects
        """
        return self.tp_dict.dereference().get_dict()
    
    def get_size(self):
        """
        Calculate the size of instances of this type.
        
        Returns:
            Either a fixed size or a function to calculate variable size
        """
        
        basic_size = self.tp_basicsize
        item_size = self.tp_itemsize
        flags = self.tp_flags

        """ Check if it's a variable-sized object"""
        if flags & (1 << 26):  # Py_TPFLAGS_HAVE_GC
            """ 
             For variable-sized objects, we need to account for the actual number of items
             However, we don't have access to the specific object instance here,
             so we'll return a function that can be called with the object's size
            """
            return lambda ob_size: basic_size + item_size * ob_size
        else:
            """ For fixed-size objects, we can just return the basic size"""
            return basic_size

class PyGetSetDescrObject(PyObject):
    
    """
    Python get/set descriptor object.
    
    Represents property getters and setters.
    """
    @property
    def d_common(self):
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_getset(self):
        return self._read_field('d_getset', 'PyGetSetDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        
        """
        Return String representation of the get/set descriptor
        """
        
        try:
            name_obj = self.d_common.d_name.dereference()
            name = name_obj.get_value()
            return f"<getset_descriptor {name}>"
        except Exception as e:
            print(f"Error processing PyGetSetDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<getset_descriptor at {hex(self.vol.offset)}>"



class PyMethodDescrObject(PyObject):
    """
    This class represents descriptor objects for methods defined in C extension 
    modules or in native Python types implemented in C. 
    
    When you access a method on a built-in type like list.append or dict.update,
    you're actually getting a method descriptor before it's bound to the instance.
    """
    
    @property
    def d_common(self):
        # Contains descriptor name and owner type information
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_method(self):
        # Points to the C function implementation details
        return self._read_field('d_method', 'PyMethodDef')

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        try:
            method_name = self.d_common.get_value()
            return f"<method_descriptor {method_name}>"
        except Exception as e:
            print(f"Error processing PyMethodDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<method_descriptor at {hex(self.vol.offset)}>"
            


class _ODictNode(objects.StructType):
    """
    OrderedDict node object.
    
    Represents a node in the ordered dictionary linked list.
    """
    
    @property
    def key(self):
        return self.member('key')

    @property
    def value(self):
        return self.member('value')

    @property
    def next(self):
        return self.member('next')

    def get_key_value(self, cur_depth=0, max_depth=10, visited=None):
        
        # Get the key-value pair for this node.
        key_obj = self.key.dereference()
        value_obj = self.value.dereference()
        key = key_obj.get_value(cur_depth + 1, max_depth, visited)
        value = value_obj.get_value(cur_depth + 1, max_depth, visited)
        return key, value


class PyMethodDef(PyObject):
    """
    Python method definition object.
    
    Represents a method definition in C code.
    """
    
    @property
    def ml_name(self):
        # Get the method name pointer
        return self._read_field('ml_name', 'char *')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            method_name = self.read_cstring(self.ml_name)
            return method_name
        except Exception as e:
            print(f"Error processing PyMethodDef at {hex(self.vol.offset)}: {str(e)}")
            return "<unknown>"



class PyGetSetDef(objects.StructType):
    """
    Python get/set definition object.
    
    Represents a property getter/setter definition.
    """
    
    def read_cstring(self, addr, max_length=256):
        """
        Read a null-terminated C string from memory.
        
        Args:
            addr: Memory address to read from
            max_length: Maximum bytes to read
            
        Returns:
            str: The string read from memory
        """
        
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

    @property
    def name(self):
        # Get the property name
        addr = int(self.member('name'))
        return self.read_cstring(addr)

    @property
    def doc(self):
        # Get the documentation string
        addr = int(self.member('doc'))
        if addr != 0:
            return self.read_cstring(addr)
        else:
            return None 
            
class PyMemberDef(objects.StructType):
    
    """
    Python member definition object.
    
    Represents a member definition in C extension types.
    """
    @property
    def name(self):
        addr = int(self._vol['name'])
        return self.read_cstring(addr)

    @property
    def doc(self):
        addr = int(self._vol['doc'])
        return self.read_cstring(addr)
    
    def read_cstring(self, addr, max_length=256):
        if addr == 0:
            return None
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length, pad=False)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

class wrapperobject(PyObject):
    """
    Python method-wrapper object.
    
    Represents a wrapper for a method bound to an instance.
    """
    
    @property
    def descr_ptr(self):
        return self.member('descr')

    @property
    def self_ptr(self):
        return self.member('self')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            # Get the descriptor object
            descr_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyWrapperDescrObject",
                layer_name=self.vol.layer_name,
                offset=int(self.descr_ptr)
            )

            # Get the method name from the descriptor
            method_name = descr_obj.get_value(cur_depth + 1, max_depth,visited)

            # Get the instance the method is bound to
            self_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
                layer_name=self.vol.layer_name,
                offset=int(self.self_ptr)
            )
            instance = self_obj.get_value(cur_depth + 1, max_depth,visited)

            return f"<bound method {method_name} of {instance}>"
        except Exception as e:
            print(f"Error processing wrapperobject at {hex(self.vol.offset)}: {str(e)}")
            return f"<method-wrapper at {hex(self.vol.offset)}>"



class PyDescrObject(PyObject):
    """
    Python descriptor object base class.
    
    Base structure for various descriptor types.
    """
    
    @property
    def d_name(self):
        return self._read_field('d_name', 'PyObject')

    @property
    def d_type(self):
        return self._read_field('d_type', 'PyTypeObject')
    
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            name_obj = self.d_name.dereference()
            name = name_obj.get_value()
            return name
        except Exception as e:
            print(f"Error processing PyDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return "<descriptor>"


class _PyNamespaceObject(PyObject):
    """
    Python namespace object.
    
    Represents a namespace (used with SimpleNamespace).
    """
    
    @property
    def ns_dict(self):
        return self.member('ns_dict')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "<namespace object (cycle detected)>"
        visited.add(obj_id)

        try:
            ns_dict_obj = self.ns_dict.dereference()
            ns_dict_value = ns_dict_obj.get_dict(cur_depth + 1, max_depth, visited)
            return ns_dict_value
        except Exception as e:
            return f"<namespace object at {hex(self.vol.offset)} (error: {str(e)})>"



class PyCellObject(PyObject):
    
    """
    Python cell object.
    
    Used for closures to store references to variables.
    """
    
    @property
    def ob_ref(self):
        return self.member('ob_ref')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "<cell object (cycle detected)>"
        visited.add(obj_id)

        ob_ref_addr = self.ob_ref
        if not ob_ref_addr or int(ob_ref_addr) == 0:
            value = None  # Cell is empty
        else:
            cell_contents = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
                layer_name=self.vol.layer_name,
                offset=int(ob_ref_addr)
            )
            value = cell_contents.get_value(cur_depth + 1, max_depth, visited)
        visited.remove(obj_id)
        return value



class PyWrapperDescrObject(PyObject):
    """
    Python wrapper descriptor object.
    
    Represents a wrapper for C-implemented methods on built-in types.
    """
    
    @property
    def d_common(self):
          return self.member('d_common')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
          #  if visited is None:
           #    visited = set()
            d_common = self.d_common
            name_obj = d_common.d_name.dereference()
            method_name = name_obj.get_value(cur_depth + 1, max_depth,visited)
            type_obj = d_common.d_type.dereference()
            type_name = type_obj.get_name()
            return method_name
        except Exception as e:
            print(f"Error processing PyWrapperDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<wrapper_descriptor at {hex(self.vol.offset)}>"


class PyMemberDescrObject(PyObject):
    """
    Python member descriptor object.
    
    Represents a descriptor for a member of a C-extension type.
    """
    @property
    def d_common(self):
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_member(self):
        return self._read_field('d_member', 'PyMemberDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            name_obj = self.d_common.d_name.dereference()
            name = name_obj.get_value()
            return f"<member_descriptor {name}>"
        except Exception as e:
            print(f"Error processing PyMemberDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<member_descriptor at {hex(self.vol.offset)}>"




class PyCFunctionObject(PyObject):
    """
    Python C function object.
    
    Represents a function implemented in C.
    """
    
    @property
    def m_ml(self):
        return self._read_field('m_ml', 'PyMethodDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """
        Get a string representation of this C function.
        """
        try:
            method_def = self.m_ml.dereference()
            method_name = self.read_cstring(method_def.ml_name)
            return f"<built-in function {method_name}>"
        except Exception as e:
            return f"<built-in function at {hex(self.vol.offset)}>"


class PyWeakReference(PyObject):
    
    """
    Python weak reference object.
    
    Represents a weak reference to another object.
    """
    @property
    def wr_object(self):
        """Get the referenced object"""
        return self._read_field('wr_object', 'PyObject')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """Get a string representation of this weak reference"""
        try:
            referent = self.wr_object.dereference()
            referent_value = referent.get_value()
            return f"<weakref to {referent_value}>"
        except Exception as e:
            return f"<weakref at {hex(self.vol.offset)}>"



class PyByteArrayObject(PyObject):
    
    """
    Python bytearray object.
    
    Represents a mutable sequence of bytes.
    """
    @property
    def ob_bytes(self):
        return self.member('ob_bytes')

    @property
    def ob_alloc(self):
        return self.member('ob_alloc')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """Get the bytearray content"""
        
        curr_layer = self._context.layers[self.vol.layer_name]
        length = int(self.ob_base.ob_size)
        data_offset = int(self.ob_bytes)
        byte_data = curr_layer.read(data_offset, length)
        return byte_data


class PyCapsule(PyObject):
    """
    Python capsule object.
    
    Used to wrap C data for Python extensions.
    """
    @property
    def pointer(self):
        # Get the C data pointer
        return self.member('pointer')

    @property
    def name(self):
        # Get the capsule name pointer
        return self.member('name')

    @property
    def context(self):
        # Get the capsule context pointer
        return self.member('context')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        # Get a string representation of this capsule
        
        name_addr = int(self.name)
        print("self.context "+str(self.context))
        name = self.read_cstring(name_addr)
        return f"<capsule object '{name}' at {hex(self.vol.offset)}>"


class PyComplexObject(PyObject):
    
    """
    Python complex number object.
    
    Represents a complex number with real and imaginary parts.
    """
    @property
    def cval(self):
        """Get the complex value structure."""
        return self.member('cval')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """Get the complex number value"""
        real = self.cval.real
        imag = self.cval.imag
        return complex(real, imag)


class enumobject(PyObject):
    """
    Python enumerate object.
    
    Represents an enumerate iterator.
    """
    @property
    def en_sit(self):
        return self.member('en_sit')

    @property
    def en_result(self):
        """Get the current result object"""
        return self.member('en_result')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """Get a string representation of this enumerate object"""
        return "<enumerate object>"



class seqiterobject(PyObject):
    
    """
    Python sequence iterator object.
    
    Represents an iterator over a sequence.
    """
    @property
    def it_seq(self):
        return self.member('it_seq')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """Get a string representation of this sequence iterator"""
        seq_obj = self.it_seq.dereference()
        seq_value = seq_obj.get_value(cur_depth + 1, max_depth, visited)
        return f"<iterator over {seq_value}>"


class calliterobject(PyObject):
    """
    Python callable iterator object.
    
    Represents an iterator over a callable (as in iter(func, sentinel)).
    """
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        #  Get a string representation of this callable iterator
        return "<callable iterator object>"

class PyModuleDef(PyObject):
    """
    Python module definition object.
    
    Represents a module definition for C extension modules.
    """
    
    @property
    def m_name(self):
        return self.member('m_name')
    @property
    def m_methods(self):
        return self.member('m_methods')
        
    @property
    def m_doc(self):
        return self.member('m_doc')
        
    @property
    def m_size(self):
        return self.member('m_size')

    def read_cstring(self, addr, max_length=256):
        if addr == 0:
            return None
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length, pad=False)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring


class PyMethodObject(PyObject):
    """
    Python method object.
    
    Represents a method bound to an instance.
    """
    @property
    def im_func(self):
        return self.member('im_func')

    @property
    def im_self(self):
        return self.member('im_self')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "<method object (cycle detected)>"
        visited.add(obj_id)

        try:
            func_obj = self.im_func.dereference()
            func_value = func_obj.get_value(cur_depth + 1, max_depth, visited)
            self_obj = self.im_self.dereference()
            self_value = self_obj.get_value(cur_depth + 1, max_depth, visited)
            return f"<bound method {func_value} of {self_value}>"
        except Exception:
            return f"<method object at {hex(self.vol.offset)}>"
        finally:
            visited.remove(obj_id)


class rangeobject(PyObject):
    """
    Python range object.
    
    Represents a range of integers.
    """
    
    @property
    def start(self):
        return self.member('start').dereference().get_value()

    @property
    def stop(self):
        return self.member('stop').dereference().get_value()

    @property
    def step(self):
        return self.member('step').dereference().get_value()

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return range(self.start, self.stop, self.step)


class PySliceObject(PyObject):
    """
    Python slice object.
    
    Represents a slice with start, stop, and step values.
    """
    @property
    def start(self):
        return self.member('start').dereference().get_value()

    @property
    def stop(self):
        return self.member('stop').dereference().get_value()

    @property
    def step(self):
        return self.member('step').dereference().get_value()

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        """ Get the slice value"""
        return slice(self.start, self.stop, self.step)

# -------------------------------------------------------------------------
# Container Objects
# -------------------------------------------------------------------------
# The following classes (PyDictObject, PyODictObject, PyListObject, PySetObject, PyTupleObject) represent Python's collection types (dict, list, set, tuple).
# Their memory structure is more complex as they need to store variable-length
# data and maintain efficient lookup mechanisms.

class PyDictObject(PyObject):
    """
    Python dictionary object.
    
    Represents a dictionary (hash table) containing key-value pairs.
    """
    @property
    def ma_values(self):
        # Get the values array pointer
        return self.member('ma_values')

    @property
    def ma_keys(self):
        # Get the keys object pointer
        return self.member('ma_keys')

    @property
    def ma_used(self):
        # Get the number of used entries
        return self.member('ma_used')
    def create_dict(self, keys, values):
        # Creates a Python dictionary given lists of keys and values
        if not keys or not values:
            return {}
        return dict(zip(keys, values))

    def get_values(self, cur_depth=0, max_depth=None, visited=None):
        #  Retrieves the addresses of values of the dict from memory 
        curr_layer = self._context.layers[self.vol.layer_name]
        addresses = []
        value_ptr = self.ma_values

        try:
            for i in range(self.ma_used):
                try:
                    addr_bytes = curr_layer.read(value_ptr + i*8, 8, pad=False)
                    addr = int.from_bytes(addr_bytes, byteorder='little')
                    addresses.append(addr)
                except exceptions.InvalidAddressException:
                    print(f"InvalidAddressException when reading value address at offset 0x{value_ptr + i*8:x}")
                    addresses.append(0)
                except Exception as e:
                    print(f"Error reading value address at offset 0x{value_ptr + i*8:x}: {str(e)}")
                    addresses.append(0)
        except Exception as e:
            print(f"Error in get_values for dictionary at {hex(self.vol.offset)}: {str(e)}")
            return addresses
        
        return addresses
    
  
    def get_dict(self, cur_depth=0, max_depth=None, visited=None):
           """
           Extracts the dictionary/map from memory.
           Tracks the current depth of recursion as well as the max recursion depth, ensuring that object creation does not loop
           Returns: A dictionary: {name : object}
           """
           result = {}
           try:
            if self.ma_values == 0:
                keys_obj = self.ma_keys.dereference()
                if not keys_obj:
                    return {}
                keys_values_tuple = keys_obj.get_keysandvalues(cur_depth, max_depth, visited)
                if keys_values_tuple is None:
                    return {}
                
                keys, value_addrs = keys_values_tuple
            else:  
                if not self.ma_keys:
                    return {}
                keys_obj = self.ma_keys.dereference()
                keys = keys_obj.get_keys(cur_depth, max_depth, visited) if keys_obj else None
                value_addrs = self.get_values(cur_depth, max_depth, visited)
                if keys is None:
                    return {}
                if value_addrs is None:
                    return {}

           except exceptions.InvalidAddressException as e:
           
            return {}
           if keys is None or value_addrs is None:
              return {}

           try:
            if max_depth is None or cur_depth < max_depth:
                # call the 'create_objects' to create Python objects from a list of memory addresses of the values
                values = create_objects(
                    self.get_symbol_table_name(),
                    self._context,
                    self.vol.layer_name,
                    value_addrs,
                    cur_depth+1,
                    max_depth,
                    visited
                )
                
            else:
                # If maximum depth is reached, do not dive deeper
                values = ['<Value (max depth reached)>' for _ in value_addrs]

           except exceptions.InvalidAddressException as e:
            
            return {}
           if values is None:
              return {}
           try:
            for key, val in zip(keys, values):
               
                if key is None:

                    continue
                key_str = str(key) if not isinstance(key, (dict, list, tuple)) else f"<unhashable {type(key).__name__}>"
                result[key_str] = val
                
            return result
           except exceptions.InvalidAddressException as e:
           
            return {}
      
class PyDictKeysObject(PyObject):
    """
    Python dictionary keys object.
    
    Internal structure that holds the keys of a dictionary.
    """
    @property
    def dk_log2_size(self):
        # Get the log2 of the dictionary size
        return self.member('dk_log2_size')

    @property
    def dk_nentries(self):
        # Get the number of entries
        return self.member('dk_nentries')

    @property
    def dk_indices(self):
        # Get the indices array
        return self.member('dk_indices')
    def get_indices_size(self):
        """
        Get the size of the indices array in bytes.
        
        Returns:
            int: Size of indices array
        """
        
        dk_size = self.dk_log2_size
        if dk_size <= 0xff:
            return dk_size
        elif dk_size <= 0xffff:
            return dk_size * 2
        elif dk_size <= 0xffffffff:
            return dk_size * 4
        else:
            return dk_size * 8

    def get_base_address(self):
        
        """
        Get the base address of the key entries.
        
        Returns:
            int: Memory address where key entries start
        """
        symbol_table_name = self.get_symbol_table_name()
        indices_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyDictKeysObject'
        ).relative_child_offset('dk_indices')
        dk_indices_size = self.get_indices_size()
        return self.vol.offset + indices_offset + dk_indices_size

    def get_keysandvalues(self, cur_depth=0, max_depth=None, visited=None):
        """
        Get both keys and values of a combined dictionary. 
        Returns:
            tuple: (list of keys, list of value addresses)
        """
        
        keys = []
        values = []

        addr = self.get_base_address()
        symbol_table_name = self.get_symbol_table_name()
        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )
            addr += 24
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
                values.append(key_entry.me_value)
        return keys, values

    def get_keys(self, cur_depth=0, max_depth=None, visited=None):
        """ Get just the keys of a dictionary"""
        
        keys = []
        addr = self.get_base_address()
        symbol_table_name = self.get_symbol_table_name()
        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
            addr += 24
        return keys

class PyDictKeyEntry(PyObject):
    """ Python dictionary key entry"""
    @property
    def me_key(self):
        # Get the key object pointer
        return self.member('me_key')

    @property
    def me_value(self):
        # Get the value object pointer
        return self.member('me_value')
    def get_key(self, cur_depth=0, max_depth=None, visited=None):
        # Get the key object
        return self.me_key.dereference().get_value(cur_depth, max_depth, visited)

class PyODictObject(PyObject):
    """
    Python OrderedDict object.
    
    Represents an ordered dictionary that remembers insertion order.
    """
    
    @property
    def od_dict(self):
        # Access the embedded PyDictObject at offset 0
        return self.member('od_dict').cast_to(
            self.get_symbol_table_name() + constants.BANG + 'PyDictObject'
        )

    @property
    def ob_type(self):
        # Access ob_type through the embedded od_dict
        return self.od_dict.ob_type

    @property
    def od_inst_dict(self):
        # Get the instance dictionary
        return self.member('od_inst_dict')

    @property
    def od_first(self):
        # Get the first node in the list
        return self.member('od_first')

    @property
    def od_last(self):
        return self.member('od_last')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        # Get the OrderedDict value
        if visited is None:
            visited = set()
       
        ordered_items = []
        # Get pointer to the first node in the linked list
        od_first_ptr = self.od_first
        if not od_first_ptr or int(od_first_ptr) == 0:
            # Empty OrderedDict case - no nodes in the list
            return collections.OrderedDict()
        # Create object for the first node in the linked list
        node = self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "_ODictNode",
            layer_name=self.vol.layer_name,
            offset=int(od_first_ptr)
        )
        # Traverse the linked list of nodes (each containing a key-value pair)
        while node and node.vol.offset != 0:
            # Extract key and value from the current node
            key, value = node.get_key_value(cur_depth + 1, max_depth, visited)
            ordered_items.append((key, value))
            # Get the next node address
            next_node_addr = node.next
            if not next_node_addr or int(next_node_addr) == 0:
                break
            # Move to the next node in the linked list
            node = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "_ODictNode",
                layer_name=self.vol.layer_name,
                offset=int(next_node_addr)
            )

     
        return collections.OrderedDict(ordered_items)



class PyListObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        #  Retrieves the variable-length Python list 
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.ob_item

        addresses = []
        # Read each pointer in the list's item array 
        for i in range(self.VAR_HEAD.ob_size):
            addr = int.from_bytes(
                curr_layer.read(data_offset + i*8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)
        # Convert the addresses to actual PyObject instances and return as a list
        return list(create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses))



class PySetObject(PyObject):

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        #  Retrieves the variable-length Python set 
        
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.table
        set_type_name = self.HEAD.ob_type.dereference().get_name()
        """ If the set is empty """
        if self.used == 0:

            return frozenset() if set_type_name == 'frozenset' else set()

        addresses = []
        # The number of slots is typically `mask + 1` 
        slot_count = self.mask + 1
        for i in range(slot_count):
            slot_offset = data_offset + i * 16  # each slot is 16 bytes (assuming 64-bit pointers)
            try:
                """
                Each slot is a setentry structure:
                key: pointer to the key object
                hash: 8-byte hash value
                """
                slot_data = curr_layer.read(slot_offset, 16, pad=False)
                
                # Extract the key address 
                key_addr = int.from_bytes(slot_data[:8], byteorder='little')

                # If the key address is 0, it indicates an empty or dummy slot 
                if key_addr == 0:
                    continue

                addresses.append(key_addr)
            except exceptions.InvalidAddressException as e:
                print(f"InvalidAddressException reading slot at {hex(slot_offset)} in PySetObject at {hex(self.vol.offset)}: {str(e)}")
            except Exception as e:
                print(f"Exception reading slot at {hex(slot_offset)} in PySetObject at {hex(self.vol.offset)}: {str(e)}")

    

        # Retrieve objects for each address 
        objects = create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses, cur_depth=cur_depth+1, max_depth=max_depth, visited=visited)
        
        # Convert all objects to hashable type if needed 
        hashed_values = []
        for idx, obj_val in enumerate(objects):
            if isinstance(obj_val, (dict, list, set, frozenset)):
                # Convert unhashable types to string representation 
                obj_str = str(obj_val)
               
                hashed_values.append(obj_str)
            else:
                hashed_values.append(obj_val)

       

        if set_type_name == 'frozenset':
            try:
                return frozenset(hashed_values)
            except TypeError as e:
                print(f"TypeError creating frozenset for PySetObject at {hex(self.vol.offset)}: {str(e)}. Returning frozenset of str() representations of values.")
                return frozenset(str(val) for val in hashed_values)
        else:
            try:
                return set(hashed_values)
            except TypeError as e:
                print(f"TypeError creating set for PySetObject at {hex(self.vol.offset)}: {str(e)}. Returning set of str() representations of values.")
                return set(str(val) for val in hashed_values)



class PyTupleObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=None, visited=None):
        # Retrieves the variable-length Python tuple
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyTupleObject'
        ).relative_child_offset('ob_item')

        addresses = []
        for i in range(self.ob_base.ob_size):
            addr = int.from_bytes(
                curr_layer.read(self.vol.offset + data_offset + i*8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)
        if max_depth is not None and cur_depth >= max_depth:
            return ['Value (max depth reached)' for _ in addresses]
        return tuple(create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses))





class PyASCIIObject(PyObject):
    """
    Python ASCII string object.
    Represents a Python string that contains only ASCII characters.
    """
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        # Extract string state flags"""
        COMPACT = (self.state >> 5) & 1
        ASCII = (self.state >> 6) & 1
        KIND = (self.state >> 2) & 0b111
        curr_layer = self._context.layers[self.vol.layer_name]
        # Determine where the string data is stored based on flags
        if ASCII and COMPACT:
            string = curr_layer.read(self.vol.offset + self.vol.size, self.length, pad=False)
        elif not ASCII and COMPACT:
            string = curr_layer.read(self.vol.offset + 72, self.length * KIND, pad=False)
        else:
            string = curr_layer.read(self.vol.offset + self.vol.size, self.length, pad=False)

        try:
            # Decode the string based on its character kind
            if KIND == 1:
                return string.decode("utf-8", errors='replace')
            elif KIND == 2:
                return string.decode("utf-16", errors='replace')
            elif KIND == 4:
                return string.decode("utf-32", errors='replace')
            else:
                return string.decode("utf-8", errors='replace')
        except UnicodeDecodeError:
           try:
             return string.decode("latin-1")
           except UnicodeDecodeError:
             return f"UNICODE_DECODE_ERROR: {string!r}"





class PyModuleObject(PyObject):
    """
    Python module object.
    
    Represents a Python module, which can be a built-in module or
    a module loaded from Python source files.
    """
    @property
    def md_state(self):
        # Get the module state
        return self.member('md_state')  
    @property
    def md_def(self):
       # Get the module definition, it reutrns 'PyModuleDef' object 
       return self.member('md_def')  
    
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
         
            module_name = self.md_name.dereference().get_value()
        except Exception:
            module_name = "Unknown"
        return f"<module '{module_name}' at {hex(self.vol.offset)}>"

    def get_dict(self, cur_depth=0, max_depth=10000, visited=None):
        if visited is None:
            visited = set()
   
       
        if int(self.vol.offset) in visited:
           
            return f"Module atttt2 {hex(self.vol.offset)}"
        visited.add(self.vol.offset)
        # Access the md_dict field of the module which is represented by 'PyDictObject' data structure
        dict_obj = self.md_dict.dereference().cast_to(
            self.get_symbol_table_name() + constants.BANG + "PyDictObject"
        )
        return dict_obj.get_dict(cur_depth + 1, max_depth, visited)
    
    def get_name(self):
        return self.md_name.dereference().get_value()
    
   

class PyPickleBufferObject(PyObject):
    """
    Python pickle buffer object.
    
    Used by the pickle module for more efficient pickling of large objects.
    """
    @property
    def view(self):
        # Get the buffer view
        return self.member('view')

    @property
    def weakreflist(self):
        # Get the weak reference list
        return self.member('weakreflist')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        # Get the buffer data
        view = self.view
        buf_addr = int(view.buf)
        length = int(view.len)

        if buf_addr == 0 or length == 0:
            return b''

        curr_layer = self._context.layers[self.vol.layer_name]
        try:
            data = curr_layer.read(buf_addr, length)
            return data
        except Exception as e:
            return f"<Error reading buffer: {str(e)}>"




class PyCodeObject(PyObject):
    """
    Represents the compiled Python code (bytecode) associated with functions, class methods, static methods, stack frames, etc.
    
    This class provides methods to extract and reconstruct Python code objects
    from memory dumps.
 
    It provides  bytecode and metadata about the code including variable names,
    constants, and source information.
    """
    
    def ensure_string_tuple(self, obj_list):
        """
        Converts a list of objects into a tuple of strings.
        This is necessary because code objects store names, varnames, etc. as
        tuples of strings, but in memory these may be stored as complex PyObjects.
        
        If an object has get_value(), use that; otherwise convert using str().
        """
        if not obj_list:
            return ()
        result = []
        for item in obj_list:
            # item might be a PyObject that should represent a string
           
            if hasattr(item, 'get_value'):
                val = item.get_value()
                if isinstance(val, str):
                    result.append(val)
                else:
                    # If val is not a string, convert to str as a fallback
                    result.append(str(val))
            else:
                # just convert directly
                if not isinstance(item, str):
                    result.append(str(item))
                else:
                    result.append(item)
        return tuple(result)

    def to_code_object(self, cur_depth=0):
        """
        Convert this PyCodeObject to a Python types.CodeType object.
        
        This method reconstructs the Python code objects from their memory representation, 
        allowing for disassembly and analysis of the actual bytecode.
        """
        
        try:
            # Convert custom integer types to standard int
            argcount = int(self.co_argcount)
            posonlyargcount = int(self.co_posonlyargcount)
            kwonlyargcount = int(self.co_kwonlyargcount)
            nlocals = int(self.co_nlocals)
            stacksize = int(self.co_stacksize)
            flags = int(self.co_flags)

            # Extract code string
            co_code_obj = self.co_code.dereference().cast_to("PyBytesObject")
            codestring = co_code_obj.get_value()

            # Extract constants
            co_consts_obj = self.co_consts.dereference()
            constants = co_consts_obj.get_value()

            # Extract names
            co_names_obj = self.co_names.dereference()
            names_list = co_names_obj.get_value(cur_depth=0, max_depth=10)
            names = self.ensure_string_tuple(names_list)

            # Extract variable names
            co_varnames_obj = self.co_varnames.dereference()
            varnames_list = co_varnames_obj.get_value(cur_depth=0, max_depth=10)
            varnames = self.ensure_string_tuple(varnames_list)

            # Extract filename
            filename_obj = self.co_filename.dereference()
            filename = filename_obj.get_value()
            if not isinstance(filename, str):
                filename = str(filename)

            # Extract function name
            name_obj = self.co_name.dereference()
            name = name_obj.get_value()
            if not isinstance(name, str):
                name = str(name)

            firstlineno = int(self.co_firstlineno)

            # Extract line number table
            co_lnotab_obj = self.co_lnotab.dereference().cast_to("PyBytesObject")
            lnotab = co_lnotab_obj.get_value()

            # Extract free variables
            co_freevars_obj = self.co_freevars.dereference()
            freevars_list = co_freevars_obj.get_value(cur_depth=0, max_depth=10)
            freevars = self.ensure_string_tuple(freevars_list)

            # Extract cell variables
            co_cellvars_obj = self.co_cellvars.dereference()
            cellvars_list = co_cellvars_obj.get_value(cur_depth=0, max_depth=10)
            cellvars = self.ensure_string_tuple(cellvars_list)

            # Create the CodeType object
            code_obj = types.CodeType(
                argcount,
                posonlyargcount,
                kwonlyargcount,
                nlocals,
                stacksize,
                flags,
                codestring,
                constants,
                names,
                varnames,
                filename,
                name,
                firstlineno,
                lnotab,
                freevars,
                cellvars
            )
            return code_obj

        except Exception as e:
            print(f"Error reconstructing code object at {hex(self.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

      
    
    def get_co_code(self):
        # Extract the raw bytecode object from the code object
        co_code_obj = self.co_code.dereference()
        return co_code_obj.cast_to("PyBytesObject")
   
    

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        #  Return the disassembled bytecode
        code = self.to_code_object()
        if code:
            disassembled_code = self.disassemble_code_with_validation(code)
            return disassembled_code
        else:
            return f"<Unable to reconstruct code object at {hex(self.vol.offset)}>"
    



class PyBoolObject(PyObject):
    #  Get the raw boolean value 
    def get_value(self, cur_depth=0, max_depth=None, visited=None):
        
        return bool(self.ob_digit)



class PyLongObject(PyObject):
    # Get the raw integer value 
    def get_sign(self, num):
        # Returns the sign of the argumen
        return -1 if num < 0 else int(bool(num))

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        sign = self.get_sign(self.VAR_HEAD.ob_size)
        if sign == 0:
            return 0
        
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        addr = self.vol.offset + self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + 'PyVarObject').size
        value = int.from_bytes(curr_layer.read(addr, 4, pad=False), byteorder='little')
        return sign * value







class PyFloatObject(PyObject):
    #  Get the  raw float value
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyFloatObject'
        ).relative_child_offset('ob_fval')

        [item] = struct.unpack('<d', curr_layer.read(self.vol.offset + data_offset, 8))
        return item

class PyFunctionObject(PyObject):

    """
    This class maps the CPython PyFunctionObject C structure to a object,
    providing access to the internal components of Python function objects in memory
    dumps. It exposes fields including code objects, globals, defaults, closures,
    and other function attributes defined in Python's funcobject.h.
    
    Each property method reconstructs a specific field from the raw memory by:
    1. Accessing the memory address of the field from the PyFunctionObject structure
    2. Creating an appropriate  object at that address
    3. Returning the object for further analysis by plugins
    
    Note: while plugins could directly access raw memory addresses of fields and create
    their own object references, this class encapsulates that logic within property
    methods. This design choice moves the object creation complexity from plugins
    into this class.
    """
    @property
    def func_code_obj(self):
        # Returns the function's code object (bytecode) used for execution
        func_code_addr = self.func_code  # Direct field access
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_code_addr
        )
 
    
    @property
    def vectorcall_obj(self):
        # Returns the vectorcall optimization structure for fast function calls
        vectorcall_addr = self.vectorcall 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=vectorcall_addr)
            
            
    @property
    def func_annotations_obj(self):
        # Returns type annotations for function parameters and return value
        func_annotations_addr = self.func_annotations 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_annotations_addr)
    @property
    def func_dict_obj(self):
        func_dict_addr = self.func_dict 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_dict_addr)
    
    @property
    def func_defaults_obj(self):
        # Return the function's default argument values tuple
        func_defaults_addr = self.func_defaults 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_defaults_addr)
    
    @property
    def func_globals_obj(self):
        # Return the globals dictionary from the function's defining scope
        func_globals_addr = self.func_globals 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_globals_addr
        )
        
    @property
    def func_doc_obj(self):
        # Return the function's docstring
        func_doc_addr = self.func_doc 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_doc_addr
        )
    
   
    @property
    def func_kwdefaults_obj(self):
        # Return the default values for keyword-only arguments
        func_kwdefaults_addr = self.func_kwdefaults 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_kwdefaults_addr
        )
    
    @property
    def func_module_obj(self):
        # Return the module object where the function is defined
        func_module_addr = self.func_module 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_module_addr
        )
    
    
    @property
    def func_qualname_obj(self):
        # Return the function's qualified name (includes class name for methods)
        func_qualname_addr = self.func_qualname 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_qualname_addr
        )
    
    
    @property
    def func_vectorcall_obj(self):
        func_vectorcall_addr = self.vectorcall 
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_vectorcall_addr
        )
    
    @property
    def func_name_obj(self):
        # Access the 'func_name' field from the structure
        func_name_addr = self.func_name  # Direct field access
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        # Return the vectorcall optimization interface (duplicate of vectorcall_obj)
  
        if max_depth is not None and cur_depth >= max_depth:
            return f"<function object (max recursion depth reached)>"

        try:
            func_name_obj = self.func_name_obj
            func_name = func_name_obj.get_value(cur_depth + 1, max_depth,visited)
           
        except Exception as e:
            func_name = "<unknown function>"
            print(f"Error retrieving func_name at {hex(self.vol.offset)}: {e}")
        return f"<function {func_name} at {hex(self.vol.offset)}>"





def create_objects(symbol_table_name, context, layer_name, addresses, cur_depth=0, max_depth=100000, visited=None):
    """
    Create Python objects from a list of memory addresses.
    
    This is a critical forensic function that:
    - Verifies each address is valid before attempting access
    - Creates the appropriate PyObject at each memory location
    - Determines each object's type by examining its ob_type field
    - Handles circular references and recursion limits
    - Gracefully manages invalid addresses or corrupted memory
    
    Args:
        symbol_table_name (str): Name of the symbol table to use
        context: Volatility context object for memory access
        layer_name (str): Name of the memory layer to read from
        addresses (list): List of memory addresses to convert to objects
        cur_depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth to prevent stack overflow
        visited (set): Set of visited addresses to prevent cycles
        
    Returns:
        list: Objects created from the provided addresses
        
    Note: This function is used extensively by dictionary, list, tuple and other
    container objects to reconstruct their contents from memory.
    """
    if visited is None:
        visited = set()

    arr = []
    for index, addr in enumerate(addresses):
        try:
           
            if addr == 0:
                # Address 0 is invalid, we handle it
                print(f"Skipping invalid address at index {index} (address=0x0).")
                arr.append(None)
                continue

            if not context.layers[layer_name].is_valid(addr, 8):
                # If the address is not valid in the current layer
                print(f"Address 0x{addr:x} at index {index} is not valid in layer {layer_name}.")
                arr.append(None)
                continue

            obj = context.object(
                object_type=symbol_table_name + constants.BANG + 'PyObject',
                layer_name=layer_name,
                offset=addr,
            )
            obj_type_name = "<unknown>"
            obj_type = obj.ob_type.dereference()
            type_name = obj_type.get_name()
            
            if hasattr(obj, 'get_type_name'):
                obj_type_name = obj.get_type_name()
            else:
                # If for some reason obj doesn't have get_type_name, fallback
                obj_type_name = type(obj)

            # Check recursion depth"""
            if max_depth is not None and cur_depth >= max_depth:
                arr.append(f"<{obj_type_name} object (max recursion depth reached)>")
            else:
                value = obj.get_value(cur_depth + 1, max_depth, visited)
                arr.append(obj)

        except exceptions.InvalidAddressException as e:
            print(f"InvalidAddressException at address 0x{addr:x} (index {index}): {str(e)}")
            arr.append(None)
        except Exception as e:
            print(f"Error in create_objects at index {index} (address 0x{addr:x}): {str(e)}")
            arr.append(None)

    return arr



def hex_bytes_to_text(value):
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")
    
    ascii = []
    for byte in value:
        if byte == 0x00:
            break
        ascii.append(chr(byte))
    
    return ''.join(ascii)




