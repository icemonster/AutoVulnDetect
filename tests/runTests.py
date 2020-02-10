#This will be done in python2 because we still care

import os
from time import time

print 'Removing all bap files'
os.system('rm bin/*.bap')
tests = os.listdir('bin')

cmdOriginal = './bin/{}'
cmdThesis = '../AutoVulnDetect bin/{}'

SUCCESS = 0
SUCCESS_APG = 0 #Random exit code

#Delete old report and create a new one
with open('report.txt','w') as f:
	pass

for test in tests:
	if os.system(cmdOriginal.format(test)) != SUCCESS:
		continue

	with open('report.txt','a') as f: 
		f.write('Testing {}\n'.format(test)) #So we know the name of the tests if we get into an infinite loop :)

	with open('report.txt','a') as f: #Dynamically generate report
		start = time()
		retCode = os.system(cmdThesis.format(test))
		end = time()
		if retCode != SUCCESS_APG:
			print '{} failed!!!! (retcode={})'.format(test, retCode)
			f.write('Test: {} has failed. time={}\n'.format(test, end-start))
		else:
			print test,'succeeded!'
			f.write('Test: {} has passed. time={}\n'.format(test, end-start))
