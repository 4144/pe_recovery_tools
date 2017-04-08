# imports_unerase
Small tool for recovering erased imports of a dumped PE file<br/>
<i>Useful in recovering executables dumped from the memory. Dedicated to cases when the imports has been erased after loading (anti-dumping trick used by malware).</i><br/>

Usage:<br>
<pre>
imports_unerase.exe [PID] [dumped_file]<br/>
PID - PID of the application from where the module was dumped<br/>
dumped_file - dumped module (in a Virtual format)
</pre>
WARNING:
This is unfinished/early beta version and it has some limitations, i.e.:<br/>
- works only for PE 32 bit
- does not support forwarded imports
