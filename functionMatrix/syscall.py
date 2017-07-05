import sys
import idaapi
import idautils
import idapython
import pickle
import time

def get_w32syscalls():
    syscalls = set()
    # def get_syscall_start():
    #     for m, n in idautils.Names():
    #         if n == '_W32pServiceTable':
    #             return m
    # ea = get_syscall_start()
    ea = idaapi.str2ea('_W32pServiceTable')
    f = idaapi.get_full_long(ea)
    functions = set(idautils.Functions())
    while f in functions:
        fname = GetFunctionName(f)         
        syscalls.add(fname)
        ea += 4
        f = idaapi.get_full_long(ea)
    print 'win32k system call' , len(syscalls)
    return syscalls

def get_ntsyscalls():
    syscalls = set()
    ea = idaapi.str2ea('_KiServiceTable')
    f = idaapi.get_full_long(ea)
    functions = set(idautils.Functions())
    while f in functions:
        fname = GetFunctionName(f)        
        syscalls.add(fname)
        ea += 4
        f = idaapi.get_full_long(ea)
    print 'ntos system call' , len(syscalls)
    return syscalls

def GetCallees(ea):
    function_eas = list(GetEAsInFunction(ea))
    visited_functions = []
    callees = []
    
    for ea in function_eas:
      xrefs = idautils.CodeRefsFrom(ea, False)
      for xref in xrefs:
        if not (xref in function_eas):
          callees.append(xref)
    return callees

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



def createsyscallslist(filename, moduleName, syscalls):
    if "win32k.sys" == moduleName:
        syscalls = get_w32syscalls()
    elif "ntoskrnl.exe" == moduleName:
        syscalls = get_ntsyscalls()
    
        
    if not os.path.exists(filename):
        with open(filename, 'w') as fw:
            pickle.dump(syscalls,fw)
    else:
        with open(filename,'r') as fr:
            oldsyscalls = set()
            oldsyscalls = pickle.load(fr)
        syscalls = syscalls|oldsyscalls
        with open(filename, 'w') as fw:
            pickle.dump(syscalls,fw)
            
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
    
'''create list'''
# createsyscallslist(filename, moduleName, syscalls)
# for x in syscalls:
#     print x
# print len(syscalls)
filename = 'syscall.pkl'
syscalls = set()

count = 0
syscallcount = {}
start = time.time()
syscalls = getsyscalls(filename)
for fea in idautils.Functions():
    syscallcount[fea] = 0
    calleetree[fea] = get_callees(fea)
    for ea in calleetree[fea]:
        fname = idc.GetFunctionName(ea)
        if fname in syscalls:
            print 'got one'
            syscallcount[fea] = syscallcount[fea]+1 #better record the syscalls name of address

for ea in syscallcount:
    print hex(ea), len(calleetree[ea]), syscallcount[ea]
    
timec = time.time() - start
print 'time consuming: ', timec
print len(syscalls)