CC = g++

main: main.cpp httpd.o
	$(CC) main.cpp httpd.o -o main

httpd.o: httpd.cpp
	$(CC) -c httpd.cpp

clean:
	rm -f main *.o
