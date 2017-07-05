Must Read Before Use:
    This tool lets you trace program running and show trace info in IDA in a graceful way.
    
    The general concept of this tool is to let users trace program running to generate a trace DB, and then use the displaying component will read the trace DB and show trace info in IDA
    
    There are several tracing modes available: (for usage details, refer to Usage below)
    
        func-count trace mode: during a program run, it traces how many times the involved functions get called. This is always the first trace mode to choose, it generates a funcCount.db which is used by other trace mode.
    
        multi-func trace mode: during a program run, it traces the instructions executed inside of the specified multi-functions. The user can specify whether he wants to trace the callee functions (other functions called from those specified multi-functions) or not.
    
        last-func trace mode: during a program run, it traces all the instructions executed after calling the specified target function (whether the instructions are inside of the function or outside of the function). The user can specify the start tracing count and end tracing count. e.g. function A() has been called 10 times (known after tracing in func-count mode), if the user specifies the start tracing count to be 5 and end tracing count to be 7, then it will trace all the instructions executed after calling A() the 5th time until A() is called the 7th time.
        
        single-func trace mode: during a program run, it traces the instructions executed inside of the specified target function (it can trace other function's instructions if step_into_callee is selected but it cannot trace instructions after the specified function has returned). Similarly to last-func trace mode, the user can specify the start traceing and end tracing count. And in addition, the user can also choose to trace the callee functions called from the specified target function.

        Note: The user must do the same operations (e.g. open the same file, do the same user clicks) to the target process in function count tracing and Last/Single function tracing to make the tracing accurate. 
    
Usage:

1. open IDA, load script (File/Script file...) RunTraceConfig.py from the tool's package, then "Trace Config" window will pop up
2. In the "Trace Config" window:
      PIN's EXE is the path of PIN's main executable, 
      Output Dir is the directory where the output files (tracing database files) reside, by default, it will automatically create a folder called "runtrace_output" in tool's package/../
      Process's EXE is the main executable of the target process to be traced, if you want to attach to a running process, just leave this field unset (*.exe).
   Press OK to finish the global settings. 
3. Press hotkey "j" (alternatively, look for Edit/Plugins/ShowRunTraceCmds) to open a command window to start with, the commands are explained below:

   Command Window:
        ShowComms: select a trace DB file to show trace comments in IDA, by default, it selects the latest (according to timestamp) trace DB file
        ListFuncCount: list all the function counts, to make this command work, the funcCount.db must exist in the output dir (set in Trace Config)
        AddFunc: Add the current (current cursor) function to the multi-function list (used only in multi-func tracing mode)
        ShowFuncList: Show all the functions of multi-function list (used only in multi-func tracing mode), you can delete some functions from this list by right clicking those functions and delete
        TraceConfig: Open the "Trace Config" window
        StartTrace: Start tracing by seleting modes, a TraceMode window will pop up:
            TraceMode Window:
                Attach Mode: you can attach to a running process by ticking and providing the process id
                Function Count: trace in func-count mode, generate funcCount.db, this is the first trace to do before trying last-func and single-func tracing mode
                Multi Function Global: trace multi-functions across the whole running of program, you can specify whether to trace the callee functions inside those selected funtions
                Multi Function Target: disabled for current release.
                Last Function: trace in last-function mode, this mode needs funcCount.db. You can specify the current function's start tracing and end tracing count (if enable end tracing option)
                Single Function: trace in single-function mode, this mode needs funcCount.db. You can specify the crrent function's tart tracing and end tracing count (if enable end tracing option) and can also specify wheter to trace the callee functions inside this function.
        StopTrace: stop tracing to generate the trace DB file. It can stop tracing anytime during the program run, no need to close the program. This is very useful to trace a background service process
        
4. Press hotkey "Shift+j" (alternatively, look for Edit/Plugins/ShowRunTraceHotKeys) to show more hotkeys used for showing trace comments in IDA
    ShowComms

	Give user some dynamic information, which include registers' value and some memory's value, to support RE.
	The data is read from a database generated by PIN. (the pin tool is context_logger.dll)

	Usage:
	HotKey (10)
	  [List all functions that have comments] Press "Shift-l"
 	  [Toggle comments] Press "Ctrl-ShLift-l"

	  [Toggle global/local index] Press "|"

	  [Select current instruction iteration] Press "i"
	  [Previous current instruction iteration] Press "["
	  [Next current instruction iteration] Press "]"

	  [Backwards view] Press "Ctrl-["        
	  [Forward view] Press "Ctrl-]"        
	  Backward and forward are specially used for loop.

	  [Previous executed instruction] Press "{"        
	  [Next executed instruction] Press "}"

	If you want to make comments, please write them before "__" index marker. 
	If you want to change the database, change it via button "ShowComms" to change the database path.('j'->ShowComms)   

Tool's File Structure:
    
    Tool's Package Files: 
        RunTrace.py: the IDA Python script to display trace comments
        RunTraceConfig.py: the IDA Python script to do tracing
        context_logger.dll: the PIN tool to do tracing
        readme.txt: this file!
        stop_trace.exe: the exe to send STOP command to PIN to stop tracing
    
    Output Files:
        moduleName_moduleExtension_funcRange.db: the start and end addresses of all the functions in this module
        moduleName_moduleExtension_funcCount.db: generated by func-count trace mode
        moduleName_moduleExtension_s_funcEntry_timestamp.db: trace DB file generated by single-function trace mode
        moduleName_moduleExtension_s_funcEntry_timestamp.log: log file for single-function trace
        moduleName_moduleExtension_l_funcEntry_timestamp.db: trace DB file generated by last-function trace mode
        moduleName_moduleExtension_l_funcEntry_timestamp.log: log file for last-function trace
        moduleName_moduleExtension_m_timestamp.db: trace DB file generated by multi-func trace mode
        moduleName_moduleExtension_m_timestamp.log: log file for multi-func trace
        moduleName_moduleExtension_m_timestamp.range: the start and end addresses of the specified multi functions
        
      