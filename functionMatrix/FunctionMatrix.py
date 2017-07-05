# ====================================================================================
# Function_Matrix is used to collect functions features.
# The features include function size, callee, caller, and cycles, etc. so far there're 12 in total, 
# but you can add more according to your requirement. For information about how to add matrix, 
# please refer to ReadMe.txt
# 
# version 1.2 on 14/10/2013, by razygon, add features function name and function address
# 
# ====================================================================================

import sys
import idaapi
import idautils
import idapython
import idc
import os
import networkx as nx
import collections
import multiprocessing
from multiprocessing import Process, freeze_support, Queue
import inspect
import pymongo
from pymongo import MongoClient
import pickle


def GetInstruction(ea):
    if ea is None:
        raise IdaPythonError("Address cannot be None")
    
    disasm = idc.GetDisasm(ea)
    
    try:
        disasm = disasm[:disasm.index(';')]
    except ValueError:
        pass
    
    if disasm == '':
        return None
    return disasm
    
            
def DEBUG_PRINT(str):
#     print '[debug info]' 
#     print  str
    return

def calc_path(dg, start, end, cutoff): #,count_conn
    count_paths = 0
    paths = nx.all_simple_paths(dg, start, end, cutoff)
    DEBUG_PRINT((start, end, cutoff))
    for x in paths:
        count_paths = count_paths + 1
#     count_conn.put(count_paths)

def DEBUG_VIEW():
    global fcan
    for f in fcan:
        print f
        print fcan[f]
    return  

class ConfirmDialog(idaapi.Form):
    def __init__(self, msg):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Confirm DB Operation
{note} 
""", {
            'note' : Form.StringLabel(msg)
        })
        
def simple_paths_count(G, source, target, cutoff=None):
    path_count = 0
    if cutoff < 1:
        return
    visited = [source]
    stack = [iter(G[source])]
    
    import time
    start = time.time()
    while stack:
        children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            visited.pop()
        elif len(visited) < cutoff:
            if child == target:
#                 yield visited + [target]
#                 print 'get one path, visited',visited
                path_count = path_count + 1
                DEBUG_PRINT(path_count)
                if path_count >= 100:
                    break
            elif child not in visited:
                visited.append(child)
                stack.append(iter(G[child]))
        else: #len(visited) == cutoff:
            if child == target or target in children:
#                 yield visited + [target]
                path_count = path_count + 1
            break
        runtime = time.time() - start
        if runtime > 20:
            return 100
#             stack.pop()
#             visited.pop()
    return path_count

def simple_cycles(G):
    """Find simple cycles (elementary circuits) of a directed graph.
    
    An simple cycle, or elementary circuit, is a closed path where no 
    node appears twice, except that the first and last node are the same. 
    Two elementary circuits are distinct if they are not cyclic permutations 
    of each other.

    Parameters
    ----------
    G : NetworkX DiGraph
       A directed graph

    Returns
    -------
    A list of circuits, where each circuit is a list of nodes, with the first 
    and last node being the same.
    """
    # Jon Olav Vik, 2010-08-09
    def _unblock(thisnode):
        """Recursively unblock and remove nodes from B[thisnode]."""
        if blocked[thisnode]:
            blocked[thisnode] = False
            while B[thisnode]:
                _unblock(B[thisnode].pop())
    
    def circuit(thisnode, startnode, component,result):
        closed = False # set to True if elementary path is closed
        path.append(thisnode)
        blocked[thisnode] = True
        for nextnode in component[thisnode]: # direct successors of thisnode
            if nextnode == startnode:
                result[startnode] = path
                DEBUG_PRINT('get one result')
                DEBUG_PRINT(result)
                closed = True
                return closed
            elif not blocked[nextnode]:
                if circuit(nextnode, startnode, component,result):
                    closed = True
        if closed:
            _unblock(thisnode)
        else:
            for nextnode in component[thisnode]:
                if thisnode not in B[nextnode]: # TODO: use set for speedup?
                    B[nextnode].append(thisnode)
        path.pop() # remove thisnode from path
        return closed
    
#    if not G.is_directed():
#        raise nx.NetworkXError(\
#            "simple_cycles() not implemented for undirected graphs.")
    path = [] # stack of nodes in current path
    blocked = collections.defaultdict(bool) # vertex: blocked from search?
    B = collections.defaultdict(list) # graph portions that yield no elementary circuit
    result = {} # list to accumulate the circuits found
    # Johnson's algorithm requires some ordering of the nodes.
    # They might not be sortable so we assign an arbitrary ordering.
    ordering=dict(zip(G,range(len(G))))
    
    count = 0
    for s in ordering:
        DEBUG_PRINT(count)
        count = count + 1
        # Build the subgraph induced by s and following nodes in the ordering
        subgraph = G.subgraph(node for node in G 
                              if ordering[node] >= ordering[s])
        # Find the strongly connected component in the subgraph 
        # that contains the least node according to the ordering
        strongcomp = nx.strongly_connected_components(subgraph)
        mincomp=min(strongcomp, 
                    key=lambda nodes: min(ordering[n] for n in nodes))
        component = G.subgraph(mincomp)
        if component:
            # smallest node in the component according to the ordering
            startnode = min(component,key=ordering.__getitem__)
            if startnode in result:
                continue 
            for node in component:
                blocked[node] = False
                B[node][:] = []
            dummy=circuit(startnode, startnode, component,result)

    return result

def get_callers(ea,maxlen=None):
    '''
    Walk through the callers recursively starting at address ea.
    maxlen is the maximum number of node the graph can contain.
    Return a dictionary of list of caller addresses.
    Return empty dictionary when number of node > maxlen.
    '''
    xtree = {}
    visited = []
    towalk = [ea]
    while towalk:
        curr = towalk.pop()
        if curr not in xtree: # the start point also will record in the tree
            xtree[curr] = []
        if curr not in visited:
            visited.append(curr)
        for x in idautils.XrefsTo(curr):
            caller = idaapi.get_func(x.frm)
            if caller:
                caller = caller.startEA
                if caller not in visited:
                    towalk.append(caller)
#             else:    #not very clear, if this is not a function, still record it??
#                 caller = x.frm
#                 xtree[caller] = []
            xtree[curr].append(caller)
        if maxlen and len(tree) > maxlen:
            return {}                    
    return xtree


def get_callees(ea,maxlen=None):
    '''
    walk through the callees recursively
    '''
    calleetree = {}
    visited = []
    towalk = [ea]
    while towalk:
        curr = towalk.pop()
        if curr not in calleetree: # the start point also will record in the tree
            calleetree[curr] = []
        if curr not in visited:
            visited.append(curr)
        for x in idapython.GetCallees(curr):
            if x not in visited:
                towalk.append(x)
#             else:    #not very clear, if this is not a function, still record it??
#                 caller = x.frm
#                 calleetree[caller] = []
            calleetree[curr].append(x)
        if maxlen and len(tree) > maxlen:
            return {}                    
    return calleetree   

def getsyscalls(filename):
    syscalls = set()
    try:
        with open(filename,'r') as fr:
            syscalls = pickle.load(fr)
    except:
        print 'oooooops, cannot load syscall list from ', filename
        raise
    if not syscalls:
        raise ValueError('syscalls list is empty')
    return syscalls

class FunctionMatrix():
    def __init__(self):  
        '''
        one table is for one function and its xref_to functions
        the table's name is the source function's name
        how to store function features within the table still need consideration
        '''
        self.script_folder = ''
        self.project_name = ''
        print '---------------------', idc.ARGV[1]
        arg = idc.ARGV[1]
        self.script_folder = arg[arg.find('(')+2: arg.find(',')-1]
        self.project_name = arg[arg.find(',')+2: arg.find(')')-1]
        print '++++++++++project_name', self.project_name                  
        print '++++++++++script_folder',self.script_folder

        self.moduleName = idc.GetInputFile().replace('.','_') #name of current idb
        if os.path.exists(self.moduleName):
            #may need user's input to decide whether rewrite it or append it? this check shld be set as input in args
            print 'the db already exist'
            clear = ConfirmDialog("Delete the current DB and create a new one?")
            clear.Compile()
            ok = clear.Execute()
            if ok:
                os.remove(self.moduleName)
            else:
                return    
        print '[Get_FunctionFeatures]moduleName:  %s'%self.moduleName
        self.func_name_ea = {name:ea for ea, name in idautils.Names()} # all names within idb
        self.ftable = collections.defaultdict(dict) # a dictionary stores the features of one function, will be refreshed for every function
        self.exports = [] # all export functions
        self.memop = {} #instructions with memory operation
        self.syscalls = set()
        
        self.priorMatrix = [('returnpoints', '_feature_returnpoints'), ('loopcount', '_feature_loopcount')]
        #(ea, writemem, writetoglobal, cmpmem, loopcalc)  
        self.LoadExports()   
        print 'table name: ' + self.moduleName
  
            
    def _CheckMemOp(self, ea):        
        '''
        the itype value are defined in .\idasdk64\include\allins.hpp
        
        op.type definition is in .\idasdk64\include\ua.hpp
        const optype_t     // Description                          Data field
              o_void     =  0, // No Operand                           ----------
              o_reg      =  1, // General Register (al,ax,es,ds...)    reg
              o_mem      =  2, // Direct Memory Reference  (DATA)      addr
              o_phrase   =  3, // Memory Ref [Base Reg + Index Reg]    phrase
              o_displ    =  4, // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
              o_imm      =  5, // Immediate Value                      value
              o_far      =  6, // Immediate Far Address  (CODE)        addr
              o_near     =  7, // Immediate Near Address (CODE)        addr
              o_idpspec0 =  8, // IDP specific type
        '''
        inst = idautils.DecodeInstruction(ea)
        if inst == None:
            return
        if inst.itype in [160,159]:
            # retn 159, retf 160
            self.ftable["returnpoints"].append(ea)            
        elif inst.itype in [122,6,209]:
            # mov 122 add 6 sub 209, write memory happened at first opr
            if 2<= inst[0].type <=7:
                #considered as memory write
                if idc.SegName(inst[0].addr) == '.idata':
                    self.ftable["memop"].append((ea,1,1,0,0))
                else:
                    self.ftable["memop"].append((ea,1,0,0,0))
        elif inst.itype in [27,210]:
                #cmp 27  test 210
                if (2<= inst[0].type <=7  and inst[0].type != 5) or (2<= inst[1].type <=7  and inst[1].type != 5):
                    #mem cmp
                    self.ftable["memop"].append((ea,0,0,1,0))
        elif inst.itype in [44,34]:
                #inc 44  dec 34;
                self.ftable["memop"].append((ea,0,0,0,1))
        elif inst.itype in [16]:
                # call 13
                if inst[0].type == 3 or inst[0].type == 4:
                    self.ftable["dynamiccall"].append(ea)
                
    def _BuildBasicBlockInfo(self, f_ea):
        f_start = f_ea
        f_end = idc.FindFuncEnd(f_start)
        
        edges = set()
        boundaries = set((f_start,))
        
        self.ftable["exceptionhandlers"] = []
        self.ftable["memop"] = []
        self.ftable["returnpoints"] = []
        self.ftable["dynamiccall"] = []
        for head in idautils.Heads(f_start, f_end): 
          # If the element is an instruction
          comm = idc.GetCommentEx(head, 1)
          if comm != None:
              if "Exception handler" in comm:
                  self.ftable["exceptionhandlers"].append(head)                          
          self._CheckMemOp(head)
          if idc.isCode(idc.GetFlags(head)):        
            # Get the references made from the current instruction
            # and keep only the ones local to the function.
            refs = idautils.CodeRefsFrom(head, 0)
            refs = set(filter(lambda x: x>=f_start and x<=f_end, refs)) 
                   
            if refs:
              # If the flow continues also to the next (address-wise)
              # instruction, we add a reference to it.
              # For instance, a conditional jump will not branch
              # if the condition is not met, so we save that
              # reference as well.
              next_head = idc.NextHead(head, f_end)
              if idc.isFlow(idc.GetFlags(next_head)):
                refs.add(next_head)
        
              # Update the boundaries found so far.
              boundaries.update(refs)
        
              # For each of the references found, and edge is
              # created.
              for r in refs:
                # If the flow could also come from the address
                # previous to the destination of the branching
                # an edge is created.
                if idc.isFlow(idc.GetFlags(r)):
                  edges.add((idc.PrevHead(r, f_start), r))
                edges.add((head, r))
        
        # Let's build the list of (startEA, startEA) couples
        # for each basic block
        sorted_boundaries = sorted(boundaries, reverse = True)
        end_addr = idc.PrevHead(f_end, f_start)
        bb_addr = []
        for begin_addr in sorted_boundaries:
            #just feel this algorithm is great
            bb_addr.append((begin_addr, end_addr))
            # search the next end_addr which could be
            # farther than just the previous head
            # if data are interlaced in the code
            # WARNING: it assumes it won't epicly fail ;)
            end_addr = idc.PrevHead(begin_addr, f_start)
            while not idc.isCode(idc.GetFlags(end_addr)):
                end_addr = idc.PrevHead(end_addr, f_start)
        # And finally return the result
        bb_addr.reverse()
        bb_edges = set()
        DEBUG_PRINT( 'BuildBasicBlockInfo' + hex(f_ea))
        for (s,e) in edges:
            sblock = [(x,y) for (x,y) in bb_addr if y==s] # x==s or 
            eblock = [(x,y) for (x,y) in bb_addr if x==e] # or y==e
            if sblock!=[] and eblock!=[]:
                bb_edges.add((sblock[0],eblock[0]))
        return bb_addr, bb_edges
    
    def _BuildDiGraph(self, f_ea):
        self.ftable["dg"] = nx.DiGraph()
        nodes,edges = self._BuildBasicBlockInfo(f_ea)
        self.ftable["dg"].add_nodes_from(nodes)
        self.ftable["dg"].add_edges_from(edges)
        return
    
    def LoadExports(self):
        for i, ordinal, ea, name in idautils.Entries():
            if not ordinal == ea:
            # by observation: ordinal == address => not exported
                self.exports.append(ea)
    
    def _feature_name(self,f_ea):
        return idaapi.get_func_name(f_ea)
    
    def _feature_ea(self, f_ea):
        return hex(f_ea)
    
    def _feature_size(self,f_ea):
        '''
        Just simply return size of the function
        +  block number
        
        prior feature: Null
        '''
        fun = idaapi.get_func(f_ea)       
        return fun.endEA-fun.startEA+1
    
    def _feature_export(self, f_ea):
        '''
        prior feature: Null
        '''
        if f_ea in self.exports:
            return 1
        else:
            return 0
        
    def _featrue_callee(self, f_ea):
        '''
        Number of calls made by this function, just one level
        
        prior feature: Null
        '''
        callees = idapython.GetCallees(f_ea)
        return len(callees),callees
    
    def _feature_callers(self,f_ea):
        '''
        Number of callers, recursively
        
        prior feature: Null
        '''
        callers = get_callers(f_ea)
        return len(callers)
    
    def _feature_exceptionhandlers(self, f_ea):
        '''
        There may exist many exception filters, but some of them share one exception handler.
        failed to generate isolated block..
        
        prior feature: Null
        '''
#         self.Ehandler[f_ea] = list(nx.isolate(self.dg[f_ea]))
        return len(self.ftable["exceptionhandlers"]),self.ftable["exceptionhandlers"]
    
    def _feature_loopcount(self, f_ea):
        '''
        Generate a block graph, then get loopcount via DiGraph.number_of_selfloops()
        
        prior feature: Null
        '''
        DEBUG_PRINT( 'feature_loopcount' + hex(f_ea))
        loopcount = 0
        mloops = set()
#         loops = map(lambda loop: sorted(loop),nx.simple_cycles(self.ftable["dg"]))
#         sorted too slow, use min instead
        self.loops = {}
        self.loops = simple_cycles(self.ftable["dg"])
#         if loops is None:
#             return 0
# #         mloops = map(lambda loop : min(loop), loops)
# #         loopcount = len(sets(mloops))
#         for loop in loops:
#             mloop = min(loop)
#             mloops.add(mloop)
#         loopcount = len(mloops)
        loopcount = len(self.loops)
        return loopcount     
   
    def _feature_returnpoints(self, f_ea):
        '''
        Number of 'ret' within the function
        rets = [addr1, addr2. ...]
        
        prior feature: Null
        '''
#         rets = []
#         for ea in idautils.FuncItems(f_ea):
#             if idaapi.is_ret_insn(ea):
#                 rets.append(ea)
#         self.ftable["returnpoints"] = rets
        DEBUG_PRINT("in returnpoints")
        fun = idaapi.get_func(f_ea)
        visited = []
        retVal = []
        for ret in self.ftable["returnpoints"]:
            towalk = [ret]
#             print 'towalk',towalk
            while towalk:
                curr = towalk.pop()
#                 print 'curr',curr
                if curr not in range(fun.startEA,fun.endEA+2): # the start point also will record int the tree
#                     print 'not in range'
                    continue
#                 print '1', hex(curr)
                if curr not in visited:
                    visited.append(curr)
                inst = GetInstruction(curr)
#                 print '2', inst
                if inst is None:
                    continue
                elif 'eax' in inst:
#                     print ret, curr, inst
                    retVal.append((ret,curr,inst))
                    continue
                for xto in idautils.XrefsTo(curr, 0):
                    DEBUG_PRINT('xto')
                    if xto.frm not in visited:
                        DEBUG_PRINT(xto.frm)
                        towalk.append(xto.frm)
        DEBUG_PRINT(retVal)
        return len(self.ftable["returnpoints"]), retVal
        
    def _feature_paths(self, f_ea):
        '''
        Number of paths from startEA to 'ret'
        The target point cannot simplely just ust the 'last' node, in most conditions, the last node is not the ret point.
        For the start point, I really also doubt whether the first node is start node.... 
        
        prior feature: returnpoints
        '''
        return 0
        paths_count = 0
        start = sorted(self.ftable["dg"].nodes())[0]
        DEBUG_PRINT('start')
        DEBUG_PRINT(start)
        cutoff = len(self.ftable["dg"])/2
        if cutoff > 70:
            return 100
        for ret in self.ftable["returnpoints"]:
            tar = None
            for (x,y) in self.ftable["dg"].nodes():
                if y == ret:
                    tar = (x,y)
                    break
            if tar != None:
                DEBUG_PRINT((start, tar, cutoff))
                paths_count = paths_count + simple_paths_count(self.ftable["dg"], start, tar, cutoff)
                if paths_count > 100:
                    break
        DEBUG_PRINT(paths_count)
        return paths_count        
#         start = sorted(self.ftable["dg"].nodes())[0]
#         print 'start' 
#         print start
#         cutoff = len(self.ftable["dg"]) -1
#         DEBUG_PRINT( 'feature_paths' + hex(f_ea))
#         for ret in self.ftable["returnpoints"]:
#             tar = None
#             for (x,y) in self.ftable["dg"].nodes():
#                 if y ==ret:
#                     tar = (x,y)
#                     break
#             #only only node will be returned
#             if tar!=None:
#                 print tar
#                 count_conn = Queue()
#                 
#                 freeze_support()
#                 PYTHON_EXE = os.path.join(sys.exec_prefix, 'pythonw.exe') #if you use python.exe you get a command window
#                 multiprocessing.set_executable(PYTHON_EXE)
#                 p = Process(target = calc_path, args = (self.ftable["dg"], start, tar, cutoff)) #,count_conn
#                 p.start()
#   
#                 p.join(5)
#                 if p.is_alive():
#                     p.terminate()
#                     count_paths = -1
# #                 else:
# #                     try:
# #                         count_paths = count_conn.get()
# #                         print 'not main_)__'
# #                     except:
# #                         count_paths = -1           
        
    
    def _feature_arg(self,ea):
        '''
        Get arguments of the funcion, this version doesn't try idc_guess_type.
        the args are stored in argstr, this list may be used in later version
        
        prior feature: Null
        '''
        typeinfo = idaapi.idc_get_type(ea)
        if typeinfo == None:
            return 0
        else:
            argstr = typeinfo[typeinfo.find('(')+1:typeinfo.rfind(')')].split(',')
            return len(argstr)
    
    def _feature_localvar(self, f_ea):
        '''
        prior feature: Null
        '''
        lvarcount = 0
        DEBUG_PRINT( 'feature_localvar' + hex(f_ea))
        try:
            id = GetFrame(f_ea)
            offset = GetLastMember(id)
        except:
            DEBUG_PRINT('no stack info for function {ea}'.format(ea =f_ea))  #BF96206A 
            return 0        
        while offset >= GetFirstMember(id):
            msize = GetMemberSize(id, offset) 
            mname = GetMemberName(id, offset)
            if mname == None:
                offset = offset - 1
            else:
                lvarcount = lvarcount +1 
#                 print mname, msize
                offset = offset - msize
                if mname == ' s':
                    lvarcount = 0
        return lvarcount
    
    def _feature_writetoglobalvar(self, f_ea):
        '''
        prior feature: Null
        '''
        lwritetog = filter(lambda x: x[2] == 1, self.ftable["memop"])
#         print 'write to global variable'
        for item in lwritetog:
            DEBUG_PRINT(item[0])
        writetog_count = len(lwritetog)
        return writetog_count,lwritetog
    
    def _feature_cmpmemory(self, f_ea):
        '''
        prior feature: Null
        '''
        lcmpmem = filter(lambda x: x[3] == 1, self.ftable["memop"])
        DEBUG_PRINT('IN cmpmemory')
        for item in lcmpmem:
            DEBUG_PRINT(hex(item[0])) 
        cmpmem_count = len(lcmpmem)       
        return cmpmem_count,lcmpmem
    
    def _feature_ClsorInstMethod(self,f_ea):
        '''
        prior feature: Null
        '''
        func_name = idaapi.get_func_name(f_ea)
        disable_mask = idc.GetLongPrm(idc.INF_LONG_DN)
        prototype = idaapi.demangle_name(func_name, disable_mask)
        if not prototype:
            return 0
        elif '__thiscall' in prototype:
            return 1
        else:
            return 0
    
    def _feature_dynamiccalls(self, default_arg):
        '''
        prior feature: Null
        '''
        return len(self.ftable["dynamiccall"]),self.ftable["dynamiccall"]
    
    #add new feature here     
    def _feature_syscalls(self,f_ea):
        '''
        get how many system calls are made within current function, which include (may not limited)
        1.direct sys call
        2.indirect call from callee recursively
        
        prior feature: null
        '''
        calleetree = {}   
        syscallcount = []
        calleetree[f_ea] = get_callees(f_ea)
        for ea in calleetree[f_ea]:
            fname = idc.GetFunctionName(ea)
            if fname in self.syscalls:#
                syscallcount.append(fname) #better record the syscalls name of address
        
        return len(syscallcount), syscallcount
    
#         for ea in function_eas:
#           xrefs = idautils.CodeRefsFrom(ea, False)
#           for xref in xrefs:
#             if not (xref in function_eas):
#               callees.append(xref)
        '''
        the above commented is one level, below is recursively
        '''

    def _feature_functiontype(self, f_ea):
        '''
        functiontype here is to identify the type of the function, now we just identify whether the function is doing memory
        operation like memcpy. later maybe we will extend the types.
        for memory operation type,the way we identify is:
            a. There're loops
            b. There're index change
                how to identify index change?
            c. Memory operation include but not limited to:
                a. Mov [eax....], ecx, lea....
                b. Stos, movs, lods
                    for 8-bit, 16-bot 
                c. Call library memory function, strcpy, ...      
    
        prior feature: loopcount
        ''' 
#         lflag = 0
        imflag = 0
        for loop in self.loops.values():
#             lflag = 1
            for block in loop:
                for l_ea in idautils.Heads(block[0],block[1]):
                    inst = idautils.DecodeInstruction(l_ea)
                    if inst == None:
                        continue
                    if inst.itype in [122]: # mov
                        # mov 122
                        if 3 == inst[0].type or 4 == inst[0].type: 
                            imflag = 1         
                    elif inst.itype in [124,207,107]: #movs/movsd, stos lods
                        # 124 movs 207 stos 107 lods
                        imflag = 1
                    elif inst.itype in [16]: # call library function
                        # 16 call
                        istr = GetInstruction(l_ea)
                        if 'strcpy' in istr or 'memcpy' in istr or 'alloc' in istr or 'free' in istr:
                            imflag = 1
        if  imflag:#lflag and    
            return 1
        else:
            return 0
        
        
    def BuildFeatureTable(self):
        '''
        walk through functions in current idb, apply all feature matrix to them.
        
        for func in functions:
            for featurefunc in featurematrix:
               get func's feature
            write to DB
            
        '''
        DEBUG_PRINT("in BuildFeatureTable")
        if self.script_folder:
            filename = self.script_folder + r'\syscall.pkl'
        else:
            filename = r'syscall.pkl'
        self.syscalls = getsyscalls(filename)
        
        flist = self.priorMatrix
        from FunctionMatrix import FunctionMatrix
        # get the function list of the class
        methods = inspect.getmembers(FunctionMatrix, predicate=inspect.ismethod)
        for method in methods:    
            if '_feature_' in method[0]:
                if method[0] in self.priorMatrix:
                    pass
                flist.append((method[0][8:].strip('_'),method[0]))
#         flist.sort()
        DEBUG_PRINT('flist: ')
        print flist
#         os.system("pause")
        
        # connect to mongo db
        client = MongoClient('localhost',24444)
        db = client[self.moduleName] # can have a higher name, project name?
        dbctrl = db[self.moduleName]  
        dbctrl.remove() # just during test/debug
        for f in self.func_name_ea.values(): #functions' start addresses
            fun = idaapi.get_func(f)
            if fun: #  
                ffeatures = collections.OrderedDict()
#                 print 'fun.startEA  and  f'
#                 print fun.startEA
#                 print f
                self._BuildDiGraph(fun.startEA)
                for fl in flist:
                    ffeatures[fl[0]] = str(getattr(self, fl[1])(f))  # []?
                DEBUG_PRINT('ffeatures')
                DEBUG_PRINT(ffeatures)
                dbctrl.insert(ffeatures)
            else:
                pass 
        db.collection_names()   
        dbctrl.count()        
        return
               

import time
start = time.time()        
fm = FunctionMatrix()
fm.BuildFeatureTable()
timec = time.time()-start
print 'time consuming: ', timec
idaapi.qexit(0)