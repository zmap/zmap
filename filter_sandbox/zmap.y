%{
#include <stdio.h>
#include <string.h>
#include "tree.h"
 
void yyerror(const char *str)
{
	fprintf(stderr,"error: %s\n",str);
	fprintf(stderr, "%s\n", "YOLO");
}
 
int yywrap()
{
	return 1;
} 
  
int main()
{
	yyparse();
} 

%}

%union {
	int int_literal;
	char *string_literal;
	struct node *expr; 
}

%token '(' ')' T_AND T_OR
%token <int_literal> T_NUMBER
%token <string_literal> T_FIELD
%token T_NOT_EQ T_GT_EQ '>' '<' '=' T_LT_EQ

%left T_OR
%left T_AND

%type <expr> filter
%type <expr> number_filter
%type <expr> string_filter
%type <expr> filter_expr


%%

filter_expr:
	filter_expr T_OR filter_expr
		{
			$$ = make_op_node(OR);
			$$->left_child = $1;
			$$->right_child = $3;
			print_expression($$);
			printf("%s\n", "");
		}
	| filter_expr T_AND filter_expr
		{
			$$ = make_op_node(AND);
			$$->left_child = $1;
			$$->right_child = $3;
			print_expression($$);
			printf("%s\n", "");
		}
	| '(' filter_expr ')'
		{
			$$ = $2;
		}
	| filter
		{
			$$ = $1;
		}
	;

filter: number_filter 
		{
			$$ = $1;
		}
	| string_filter
		{
			$$ = $1;
		}
	;

number_filter: T_FIELD '=' T_NUMBER
		{
			printf("number_filter: %s = %d\n", $1, $3);
			$$ = make_op_node(EQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}	
	| 
	T_FIELD '>' T_NUMBER
		{
			printf("number_filter: %s > %d\n", $1, $3);
			$$ = make_op_node(GT);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	|
	T_FIELD '<' T_NUMBER
		{
			printf("number_filter: %s < %d\n", $1, $3);			
		}
	|
	T_FIELD T_NOT_EQ T_NUMBER
		{
			printf("number_filter: %s != %d\n", $1, $3);
		}
	|
	T_FIELD T_GT_EQ T_NUMBER
		{
			printf("number_filter: %s >= %d\n", $1, $3);
		}
	|
	T_FIELD T_LT_EQ T_NUMBER
		{
			printf("number_filter: %s <= %d\n", $1, $3);
		}
	;

string_filter:
	T_FIELD '=' T_FIELD
		{
			printf("string_filter %s = %s\n", $1, $3);
		}
	|
	T_FIELD T_NOT_EQ T_FIELD
		{
			printf("string_filter: %s != %s\n", $1, $3);
		}
	;

%%


