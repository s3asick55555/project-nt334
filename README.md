# Memory Analysis of the Python Runtime Environment

This repo is based on [this repo](https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis.git), Following the paper of: 
Memory Analysis of the Python Runtime Environment to appear in DFRWS US, 2025 with some minor adjustments

## Plugins
- **Py_Class**:  Analyzes the data structures of the application classes and provides detailed information about their attributes, objects, and instances. 
- **Py_Module**: Aanalyzes the data structures of the application modules  and provides detailed information about their packages, initialization status, and file paths.
- **Py_Function**: Analyzes the data structures of the application functions and provides details about their names, parent modules, and source file locations. 
- **Py_Code**:  Analyzes  the data structures of the  bytecode associated with the application functions and  provides details about the number of its  arguments,  number of locals variables, names of variables, and disassembled bytecode.
- **Py_Stack_Call**: Analyzes  the data structures of the stack frames to reconstruct  the execution traces of the application.
- **Py_Stack_Var**:   Analyzes the  `f_localsplus` array of the stack frame to extract runtime values of  its local variables.
- **Py_Report**: Combine the results of `Py_Class`, `Py_Module`, `Py_Function` and `Py_Code` into a JSON file and then unify the result for process with LLMs. For now only works with Windows.


## The Core: Python Symbol Table
  The **python_symbol_table.py** represents the cornerstone of this plugin suite, mapping Python's internal memory structures to Volatility 3 classes. This file:
  - Defines Python object classes mirroring CPython's internal structures.
  - Implements memory parsing logic for all Python types (strings, dicts, lists, etc.).
  - Handles complex memory layouts, including garbage collection chains.
  - Provides recursive value extraction with cycle detection.
  - Contains bytecode disassembly functionality.
  - Provide  stack frame and execution state reconstruction.

## Requirments

### Plugins
- Python 3.8 until 3.10 (due to how code objects are presented, Python 3.11 and above will not work.)
- Volatility 3 Framework
- For Linux memory analysis: appropriate debugging symbols

### Agents
- Python 3.10 or higher
- OpenRouter AI and Gemini API keys

## Setting Up the Plugins
The plugins are designed to work with an existing Volatility 3 installation. Follow these steps to set them up:
1. First, ensure Volatility 3 is correctly installed on your system: ```python3 vol.py -h```
   If this command runs successfully and displays the Volatility help menu, your installation is working properly.

2. The plugins need to be placed in specific directories based on the target operating system:
 -  For Linux memory analysis : ```/path/to/volatility3/volatility3/framework/plugins/linux/```
 -  For Windows memory analysis : ```/path/to/volatility3/volatility3/framework/plugins/windows/```

3. Add Required Dependencies: The plugins require specific symbol-finder plugins to locate the "_PyRuntime" symbol:
  - Windows plugins depend on the existing `pe_symbols` plugin to locate `_PyRuntime`.
  - Linux plugins require our custom `elf_symbols` plugin to locate this symbol in the dynamic table of the ELF header.
  - Note: You can find the 'elf_symbols' plugin in Linux_Plugins directory. Its code is documented step by step, explaining how it parses the ELF header and accesses the _PyRuntime symbol.

4. Confirm that Volatility can recognize the newly added plugins:```python3 vol.py -h | grep Py_```
   You should see all the Python memory forensics plugins listed.

5. To use **Py_Report** plugin, run `python3 vol.py -f <memdump> windows.py_report --pid <pid> --report-file <output-file>.json`

6. Run `finalize_report.py` to summerize the output and list out potential IOCs.


# Reference

Ali, H., Case, A., & Ahmed, I. (2025). Memory Analysis of the Python Runtime Environment. Forensic Science International: Digital Investigation, 53, 301920. https://doi.org/10.1016/j.fsidi.2025.301920