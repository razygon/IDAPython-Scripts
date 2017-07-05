Function_Matrix
------------------
#Description

Function_Matrix is used to collect functions features within idb, the features include function size, callee, caller, and cycles, etc. so far there're 17 in total, but you can add more according to your requirement.

This tool has two separate part: Data Collection and Data Read. Data collection is implemented in batch manner, the data collected will be used in a complicated algorithm analysis to get a score for each function, which is to measure the vulnerable level.
while data read is make data visible to user during manual analysis within one idb.

#Setup
	1. IDA Pro 6.4
	2. Python 2.7
	3. Mongodb, install pymongo(python)

#Usage
====================================Data Collection==========================================
	python StartFM.py [-p project_name] [-t target_folder]
	
	-[project_name]  ***REQUITRED***
		Name of the result folder, which is used to store result. 
		
	-[target_folder] ***REQUIRED***
		if is a idb file: just keep its extension 'idb'
		if is a folder:  Installation folder of your Target with quotes (e.g "C:\Program Files\Adobe" )
		if is a file: each line contains a folder as above  ***
	
===================================Data Read=================================================
	Load extractFunMatrix.py into idb. Follow the instructions, which include give the database's address, etc.
	##HotKey 
		'Ctrl-Shift-f'
	Input the function name OR a string you want to look. No input or space is not allowed will return no result.
	If some functions are matched, a list windows will pop out. Click the one you are interested, you can see more detailed info in the output window.
	
# ADD new matrix
	when you want to add new matrix, what you need to do is add one function within class FunctionMatrix. The function looks like:
		def _feature_[featurename](self,f_ea):
			
			# function body
			
			return [return value]

	-[featurename]: name of the new added feature
	[]: return the result of the feature
	And of course, you can make use of existed variables to build the new feature. You can find them within __init__ of class FunctionMatrix,
	and comments are there to give you better understanding.

	example:
		def _feature_callers(self,f_ea):
			'''
			Number of callers, iteratively
			'''
			callers = get_xrefTo(f_ea)
			return len(callers)

