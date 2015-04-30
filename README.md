# KMS

Mikey-Sakke Key Material generator (RFC 6507, 6508, 6509)

Note! If you are viewing this page on the github web page, there is a wiki link on the right hand side of the project screen that provides more details.
Overview

Overview
--------
This code performs the ECCSI/ Sakke dialogs as defined in RFCs 6507-6508.


Points to note:
     o It was/ is a personal project. It could do with a serious amount of 
       code review.
     o You will also need to clone and build the associated ECCSI-SAKKE
       project in order to build this project. This is because this 
       project uses some of the crypto and data storage code provided
       by the ECCSI-SAKKE crypto library.
     o There is no interaction with a clients.
     o It is C and OpenSSL (no other maths libraries). As such, this makes 
       it a tad slower, but this should have limited or no effect in the 
       KMS, as these calculation will be done infrequently offline.

Other things to note with this implementation:
          
     o If you want to turn DEBUG output off, comment out the following line: 
          
          #define ES_OUTPUT_DEBUG
      
       from src/utils/log.h __in the ECCSI_SAKKE project and rebuild it__.
     o If you want to change where data (community and user key data) you 
       will need to modify STORAGE_ROOT in inc/globals.h again __in the
       ECCSI-SAKKE project and rebuild it__.
     o In the make file you need to tell the make script where it can find 
       the ECCSI-SAKKE crypto library files. To do this you modify the 
       __ECCSI_SAKKE_DIR__ attribute in the _make-kms_ file, for example:
       
       ECCSI_SAKKE_DIR=/home/_myname_/ECCSI-SAKKE

Making
------

Prep (linux):
    The make script needs to be executable and as I am new to git hub,
    it does not seem immediately obvious how to (or even if you can) do 
    this. So, when you have cloned the repo, do:

        chmod 775 make

 To make (linux):

    ./make

Note! It is worth having a read of the make file as well. 

Running
-------

To run:

     ./kms

Note! You will need to do the following first before running:
          
          export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path-to-where-you-installed-ECCSI-SAKKE>/lib
          
refer to make script file for more details.

Doxygen
-------

For doxygen documentation:

    Install:
        yum install graphviz
        yum install boost-graph
        yum install texlive
        yum install texlive-utils
        yum install doxygen

Then:
    doxygen Doxyfile

Next, web browser and open file 
    file://<path-to-this-dir>/doxygen_output/html/index.html

Contact Details
---------------

jim<AT>mikey-sakke.org
