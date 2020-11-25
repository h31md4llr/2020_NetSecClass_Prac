all : 1m-block

1m-block : main.o
	g++ -o 1m-block main.o -lnetfilter_queue

main.o : main.cpp

clean:
	rm *.o 1m-block
