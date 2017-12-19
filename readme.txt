

*********System Integration Verifier(SIV)*****************

System Integration verifier is a simple program which detects file system modifications with in a directory tree.

SIV warns about any changes to a report file 

how to use:

You may need to be a root user to run SIV, as some files don't have a read/write access rights.


[1] Run SIV in "initialization mode

   the first command line option should be <-i>
   Command line command:
   python SIV.py -i --dir <monitored path> --ver <verification file> --rep <report file> --hash  <hash function>
   


   three types of hash functions are implemented. i.e. sha1, md5 and sha256

[2] Run SIV in "Verification mode
  
  The first command line option should be -v
  Command line command:
   python SIV.py -i --dir <monitored path> --ver <verification file> --rep <report file> --hash  <hash function>

 
Report file will be generated in the specified folder i.e. the folder specified by the user.



