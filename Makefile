all:
	g++ x509_test.cpp -o x509_test -lssl -lcrypto -ldl -lcurses
	
clean:
	rm -f x509_test