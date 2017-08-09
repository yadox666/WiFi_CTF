if HAVE_DOXYGEN

doxyfile.stamp: ../src/tm1638.h ../src/tm1638.c
	$(DOXYGEN) Doxyfile
	echo Timestamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp *~

all-local: doxyfile.stamp

clean-local:
	rm -rf html
endif 
