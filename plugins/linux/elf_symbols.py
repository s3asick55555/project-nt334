import logging
from typing import Dict, Tuple, List, Generator, Optional, Set
from volatility3.framework import interfaces, exceptions, constants
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux import lsmod
vollog = logging.getLogger(__name__)

class ELFSymbolFinder(interfaces.plugins.PluginInterface):
    """
    Plugin for efficiently finding specific symbols (like _PyRuntime) in ELF binaries from memory dumps.
    
    This plugin traverses process memory spaces and kernel modules to find ELF binaries,
    then efficiently searches their symbol tables for specific symbols. It's optimized for
    memory forensics where only specific symbols are needed rather than full ELF parsing.
    
    The primary use case is supporting Python memory forensics by locating critical runtime 
    structures like '_PyRuntime', PyInterpreterState, and similar symbols. These symbols provide 
    entry points for deeper analysis of Python processes in memory dumps.
    
    Key features:
     - Lightweight ELF parsing (only reads necessary structures)
     - Handles both 32-bit and 64-bit ELF formats
     - Can search in process memory and kernel modules
     - Uses dynamic section's symbol and string tables for efficient lookup
     - Extracts detailed symbol information (address, size, type, binding)
     - Handles PIE/ASLR by calculating correct virtual addresses
     - Implements safety limits to prevent excessive processing

   """
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """
        Define the configuration requirements for this plugin to run.
        
        This method specifies the inputs needed for the plugin, including:
        - Linux kernel module for memory access
        - Module name to search for (e.g., python3.8)
        - Symbol name to look for (default: _PyRuntime)
        - Flag for exact symbol name matching
        - Location to search (processes/kernel/both)
        
        Returns:
            List of requirement objects defining the plugin's configuration needs
        """
        
        
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.StringRequirement(
                name="module_name",
                description="Name of the module to analyze",
                optional=False,
            ),
            requirements.StringRequirement(
                name="symbol",
                description="Symbol to search for (e.g., _PyRuntime)",
                optional=True,
                default="_PyRuntime"
            ),
            requirements.BooleanRequirement(
                name="exact_match",
                description="Only find exact symbol matches (default: True)",
                optional=True,
                default=True
            ),
            requirements.ChoiceRequirement(
                name="source",
                description="Where to search for modules",
                choices=["processes", "kernel", "both"],
                optional=True,
                default="processes",
            ),
        ]

    @staticmethod
    def get_kernel_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[Set[str]] = None
    ) -> Dict[str, List[Tuple[str, int, int]]]:
        """
        This method uses the lsmod plugin to find loaded kernel modules
        and filters them based on the provided module names.
         For each matching module, it records the memory layer, base address, and size.
        
        Args:
            context: The Volatility context
            layer_name: Name of the memory layer
            symbol_table: Name of the symbol table
            filter_modules: Set of module names to find (case-insensitive)
            
        Returns:
            Dictionary mapping module names to lists of (layer_name, start_address, size) tuples
        """
        kernel_modules = {}
        # Get list of loaded modules
        kmod_list = lsmod.Lsmod.list_modules(context, layer_name, symbol_table)
        
        for module in kmod_list:
            mod_name = module.name.string.lower()
            
            if filter_modules and mod_name not in filter_modules:
                continue
                
            if mod_name not in kernel_modules:
                kernel_modules[mod_name] = []
                
            kernel_modules[mod_name].append(
                (layer_name, module.module_core, module.module_size)
            )
            
        return kernel_modules
    
    @staticmethod
    def get_process_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[Set[str]] = None
    ) -> Dict[str, List[Tuple[str, int, int]]]:

        """
        This method scans all processes in memory, examines their virtual memory areas,
        and identifies those that contain ELF binaries. It filters based on the binary
        names to find modules of interest.
        
        Args:
            context: The Volatility context
            layer_name: Name of the memory layer
            symbol_table: Name of the symbol table
            filter_modules: Set of module names to find (case-insensitive)
            
        Returns:
            Dictionary mapping module names to lists of (proc_layer_name, start_address, size) tuples
        """
        process_modules = {}
        processes = pslist.PsList.list_tasks(context, "kernel")
        for proc in processes:
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
                
            # For each process, get memory maps
            try:
                for vma in proc.mm.get_vma_iter():
                    proc_layer = context.layers[proc_layer_name]
                    
                    # Check if the memory region contains an ELF header
                    try:
                        header = proc_layer.read(vma.vm_start, 4, pad=True)
                        if header != b"\x7fELF":
                            continue
                    except exceptions.InvalidAddressException:
                        continue
                        
                    # Get the module name from the file path
                    path = vma.get_name(context, proc)
                    if not path:
                        continue
                        
                    mod_name = path.split('/')[-1].lower()
                    
                    if filter_modules and mod_name not in filter_modules:
                        continue
                        
                    if mod_name not in process_modules:
                        process_modules[mod_name] = []
                        
                    process_modules[mod_name].append(
                        (proc_layer_name, vma.vm_start, vma.vm_end - vma.vm_start)
                    )
            except exceptions.InvalidAddressException:
                continue
                
        return process_modules

    def _parse_elf_header(self, elf_table_name: str, layer_name: str, module_start: int) -> Dict:
        # Parse just enough of the ELF header to locate the dynamic section
        result = {
            "valid": False,
            "ei_class": None,
            "ph_offset": None,
            "ph_size": None,
            "ph_count": None,
        }
        
        try:
            # Read and verify ELF magic bytes and identification section
            e_ident = self.context.layers[layer_name].read(module_start, 16)
            if e_ident[:4] != b'\x7fELF':
                return result
            
            # Parse EI_CLASS to determine 32 or 64 bit 
            ei_class = e_ident[4]
            result["ei_class"] = ei_class
            
            # Choose appropriate ELF header type based on class 
            header_type = "Elf64_Ehdr" if ei_class == 2 else "Elf32_Ehdr"
            
            # Access the ELF header through Volatility3's object system 
            elf_header = self.context.object(
                elf_table_name + constants.BANG + header_type, 
                offset=module_start,
                layer_name=layer_name
            )
            
            # Get only what we need for finding the program headers 
            result["valid"] = True
            result["type"] = elf_header.e_type
            result["ph_offset"] = module_start + elf_header.e_phoff
            result["ph_size"] = elf_header.e_phentsize
            result["ph_count"] = elf_header.e_phnum
            
        except Exception as e:
            vollog.debug(f"Error parsing ELF header: {str(e)}")
            
        return result
        
    def _find_dynamic_section(self, elf_table_name: str, layer_name: str, ph_info: Dict) -> Dict:
        # Find only the dynamic section in program headers
        if not ph_info.get("valid"):
            return None
            
        # Choose appropriate program header type based on ELF class
        phdr_type = "Elf64_Phdr" if ph_info["ei_class"] == 2 else "Elf32_Phdr"
        
        dynamic_section = None    
        for i in range(ph_info["ph_count"]):
            try:
                ph_addr = ph_info["ph_offset"] + (i * ph_info["ph_size"])
                ph = self.context.object(
                    elf_table_name + constants.BANG + phdr_type, 
                    offset=ph_addr, 
                    layer_name=layer_name
                )
                
                """ Only interested in the dynamic section (PT_DYNAMIC = 2)"""
                if ph.p_type == 2:
                    dynamic_section = {
                        "type": ph.p_type,
                        "vaddr": ph.p_vaddr,
                        "memsz": ph.p_memsz,
                    }
                    break
                    
            except Exception as e:
                vollog.debug(f"Error parsing program header at index {i}: {str(e)}")
                
        return dynamic_section
        
    def _extract_dynamic_entries(self, elf_table_name: str, layer_name: str, 
                          module_start: int, dynamic_addr: int, dynamic_size: int, 
                          ei_class: int, target_tags=(5, 6, 10, 11)) -> Dict:
      """
       Extract only the relevant entries from the dynamic section
       We only need:
       DT_STRTAB (5) - String table address
       DT_SYMTAB (6) - Symbol table address
       DT_STRSZ (10) - String table size
       DT_SYMENT (11) - Symbol entry size
      """
      results = {5: None, 6: None, 10: None, 11: None}
      
      # Choose appropriate dynamic entry type based on ELF class
      dyn_type = "Elf64_Dyn" if ei_class == 2 else "Elf32_Dyn"
      full_dyn_type = elf_table_name + constants.BANG + dyn_type
      
      offset = 0
      dyn_entry_size = 16  # Size of Elf64_Dyn or Elf32_Dyn
      
      while offset < dynamic_size:
        try:
            # Read tag directly from memory
            tag_bytes = self.context.layers[layer_name].read(dynamic_addr + offset, 8)
            tag = int.from_bytes(tag_bytes, byteorder='little')
            
            # DT_NULL (0) marks the end of the dynamic section
            if tag == 0:
                break
                
            # Only process entries we care about
            if tag in target_tags:
                val_bytes = self.context.layers[layer_name].read(dynamic_addr + offset + 8, 8)
                val = int.from_bytes(val_bytes, byteorder='little')
                results[tag] = val
                
                # If we have all the entries we need, stop searching
                if all(results.values()):
                    break
            
            # Move to next entry
            offset += dyn_entry_size
            
        except Exception as e:
            vollog.debug(f"Error reading dynamic entry at {hex(dynamic_addr + offset)}: {str(e)}")
            break
    
      return results

    def _find_symbol(self, layer_name: str, symtab_addr: int, strtab_addr: int, 
                   strtab_size: int, syment_size: int, ei_class: int, target_symbol: str) -> List[Dict]:
      """
      Find a specific symbol in the dynamic symbol table.
      
      This method directly parses the symbol table entries and string table
      to locate symbols matching the target name, avoiding the overhead of
      parsing the entire table.
      
      Args:
          layer_name: Name of the memory layer
          symtab_addr: Address of the symbol table
          strtab_addr: Address of the string table
          strtab_size: Size of the string table
          syment_size: Size of each symbol table entry
          ei_class: ELF class (1 = 32-bit, 2 = 64-bit)
          target_symbol: Symbol name to search for
          
      Returns:
          List of dictionaries with info about matching symbols
      """
      found_symbols = []
      
      # Size of the name offset field in the symbol entry
      name_offset_size = 4  # Same for 32 and 64-bit ELF
      
      i = 0
      # Safety limit to prevent excessive processing
      # This limit can be adjusted if needed for extremely large ELF files
      max_entries = 50000  
      
      while i < max_entries:
        try:
            #Calculate the offset of this symbol
            sym_offset = symtab_addr + (i * syment_size)
            
            # Read the name offset field directly
            name_offset_bytes = self.context.layers[layer_name].read(sym_offset, name_offset_size)
            name_offset = int.from_bytes(name_offset_bytes, byteorder='little')
            
            if name_offset == 0:
                i += 1
                continue
                
            #Try to read the symbol name from the string table
            try:
                name_addr = strtab_addr + name_offset
                name_bytes = b""
                max_name_len = 128  # Reasonable limit for symbol name
                
                # Read until null terminator or max length
                for j in range(max_name_len):
                    char = self.context.layers[layer_name].read(name_addr + j, 1)
                    if char == b"\x00":
                        break
                    name_bytes += char
                
                name = name_bytes.decode("utf-8", errors="replace")
                
                # Check if this matches our target symbol - either exact match or contains
                exact_match = self.config.get("exact_match", True)
                if (exact_match and name == target_symbol) or (not exact_match and target_symbol in name):
                    # For a matching symbol, read the full symbol entry
                    symbol_bytes = self.context.layers[layer_name].read(sym_offset, syment_size)
                    
                    # Extract the value/address field (at offset 8 in 64-bit, 4 in 32-bit)
                    value_offset = 8 if ei_class == 2 else 4
                    value_size = 8 if ei_class == 2 else 4
                    value = int.from_bytes(symbol_bytes[value_offset:value_offset+value_size], byteorder='little')
                    
                    # Extract the size field (after the value field)
                    size_offset = value_offset + value_size
                    size = int.from_bytes(symbol_bytes[size_offset:size_offset+value_size], byteorder='little')
                    
                    # Extract the info byte for type and binding (at offset 4 in 64-bit, 12 in 32-bit
                    info_offset = 4 if ei_class == 2 else 12
                    info = symbol_bytes[info_offset]
                    binding = info >> 4
                    sym_type = info & 0xF
                    
                    # Map binding and type to human-readable values
                    binding_map = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
                    binding_str = binding_map.get(binding, f"UNKNOWN ({binding})")
                    
                    type_map = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
                    type_str = type_map.get(sym_type, f"UNKNOWN ({sym_type})")
                    
                    found_symbols.append({
                        "name": name,
                        "address": value,
                        "size": size,
                        "type": type_str,
                        "binding": binding_str,
                        "index": i
                    })
                    
            except Exception as e:
                vollog.debug(f"Error reading symbol name at offset {name_offset}: {str(e)}")
            
            i += 1
                
        except Exception as e:
            vollog.debug(f"Error parsing symbol at index {i}: {str(e)}")
            break
    
      return found_symbols

    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
      """
      Main generator function that drives the plugin execution.
      
      This method:
      1. Gets configuration options
      2. Searches for modules in process/kernel memory
      3. Analyzes ELF structures in each module
      4. Locates target symbols
      5. Yields results for display
      
      Yields:
          Tuples containing depth and data for the TreeGrid renderer
      """
      
      # Get configuration
      module_name = self.config["module_name"].lower()
      target_symbol = self.config["symbol"]
      exact_match = self.config.get("exact_match", True)
      filter_modules = {module_name}
      
      yield (0, (f"Searching for{' exact match of ' if exact_match else ' '} symbol '{target_symbol}' in module {module_name}", "", "", ""))
      
      # Get the kernel module
      kernel = self.context.modules[self.config["kernel"]]
      
      # Create ELF symbol table
      elf_table_name = intermed.IntermediateSymbolTable.create(
        self.context, self.config_path, "linux", "elf", class_types=elf.class_types
      )
      
      found_modules = {}
      
      # Determine which sources to search based on config
      source = self.config.get("source", "processes")
      
      # Search in process memory if requested
      if source in ["processes", "both"]:
        process_modules = self.get_process_modules(
          self.context, 
          kernel.layer_name,
          kernel.symbol_table_name,
          filter_modules
        )
        found_modules.update(process_modules)
      
      # Search in kernel modules if requested
      if source in ["kernel", "both"]:
        kernel_modules = self.get_kernel_modules(
          self.context, 
          kernel.layer_name,
          kernel.symbol_table_name,
          filter_modules
        )
        found_modules.update(kernel_modules)
      
      # If no modules were found, report and exit
      if not found_modules:
        yield (0, (f"Module {module_name} not found in memory", "", "", ""))
        return
      
      # Process each found module instance
      for mod_name, module_instances in found_modules.items():
        for instance_idx, module_info in enumerate(module_instances):
            layer_name, module_start, module_size = module_info
            
            yield (0, (f"Searching for symbol '{target_symbol}' in {mod_name} instance {instance_idx+1} at {hex(module_start)}", "", "", ""))
            
            # 1. Parse minimal ELF header
            header_info = self._parse_elf_header(elf_table_name, layer_name, module_start)
            
            if not header_info["valid"]:
                yield (0, (f"Invalid ELF header at {hex(module_start)}", "", "", ""))
                continue
            
            # 2. Find the dynamic section
            dynamic_section = self._find_dynamic_section(elf_table_name, layer_name, header_info)
            
            if not dynamic_section:
                yield (0, (f"No dynamic section found in {mod_name} at {hex(module_start)}", "", "", ""))
                continue
            
            # Calculate the dynamic section address correctly
            if header_info["type"] == 0x03:  # ET_DYN (shared object/PIE)
                dynamic_addr = module_start + dynamic_section["vaddr"]
            else:  # ET_EXEC or others
                dynamic_addr = dynamic_section["vaddr"]
                
            dynamic_size = dynamic_section["memsz"]
            
            # 3. Extract only the information we need from the dynamic section
            dyn_info = self._extract_dynamic_entries(
                elf_table_name, layer_name,
                module_start, dynamic_addr, dynamic_size,
                header_info["ei_class"]
            )
            
            # Check if we have all the required information
            if not all(dyn_info.values()):
                missing = [k for k, v in dyn_info.items() if v is None]
                yield (0, (f"Missing required dynamic entries in {mod_name}: {missing}", "", "", ""))
                continue
            
            # 4. Get the addresses of the symbol and string tables
            symtab_addr = dyn_info[6]  # DT_SYMTAB
            strtab_addr = dyn_info[5]  # DT_STRTAB
            strtab_size = dyn_info[10]  # DT_STRSZ
            syment_size = dyn_info[11]  # DT_SYMENT
            
            # 5. Search directly for the target symbol
            symbols = self._find_symbol(
                layer_name, symtab_addr, strtab_addr, strtab_size, syment_size,
                header_info["ei_class"], target_symbol
            )
            
            if not symbols:
                yield (0, (f"Symbol '{target_symbol}' not found in {mod_name}", "", "", ""))
            else:
                yield (0, (f"Found {len(symbols)} matching symbols in {mod_name}:", "", "", ""))
                
                for sym in symbols:
                    # Output the symbol information
                    yield (1, (f"[{sym['index']}] {sym['name']}", 
                             f"Address: 0x{sym['address']:x}", 
                             f"Size: {sym['size']} bytes", 
                             f"Type: {sym['type']}, Binding: {sym['binding']}"))
                    
                    # If symbol is an OBJECT type, try to read some data at that address
                    if sym['type'] == "OBJECT" and sym['size'] > 0:
                        try:
                            # For objects, read a sample of the data (first 64 bytes or less)
                            sample_size = min(64, sym['size'])
                            data = self.context.layers[layer_name].read(sym['address'], sample_size)
                            
                            # Check if it contains pointers (looking for values that could be addresses)
                            pointers = []
                            for i in range(0, len(data) - 8, 8):
                                ptr_val = int.from_bytes(data[i:i+8], byteorder='little')
                                if 0x400000 <= ptr_val <= 0x7FFFFFFFFFFF:  # Simple heuristic for valid pointers
                                    pointers.append((i, ptr_val))
                            
                        except Exception as e:
                            yield (2, (f"Could not read object data: {str(e)}", "", "", ""))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Name", str),
                ("Info1", str),
                ("Info2", str),
                ("Info3", str),
            ],
            self._generator(),
        )
