all:
	gcc -c tree.c -o tree.o
	lex zmap.l
	yacc -d --debug --verbose zmap.y
	gcc tree.o lex.yy.c y.tab.c -o test

clean:
	rm *.o a.out test
