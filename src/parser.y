%{
#include <stdio.h>
#include <string.h>
#include "expression.h"
#include "lexer.h"
#include "filter.h"

void yyerror(const char *str)
{
	fprintf(stderr,"Parse error: %s\n",str);
}
 
int yywrap()
{
	return 1;
}

extern node_t *zfilter;

%}

%union {
	int int_literal;
	char *string_literal;
	struct node_st *expr; 
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

expression: filter_expr
	{
		zfilter = $1;
	}


filter_expr:
	filter_expr T_OR filter_expr
		{
			$$ = make_op_node(OR);
			$$->left_child = $1;
			$$->right_child = $3;
		}
	| filter_expr T_AND filter_expr
		{
			$$ = make_op_node(AND);
			$$->left_child = $1;
			$$->right_child = $3;
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
			$$ = make_op_node(EQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}	
	| 
	T_FIELD '>' T_NUMBER
		{
			$$ = make_op_node(GT);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	|
	T_FIELD '<' T_NUMBER
		{
			$$ = make_op_node(LT);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	|
	T_FIELD T_NOT_EQ T_NUMBER
		{
			$$ = make_op_node(NEQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	|
	T_FIELD T_GT_EQ T_NUMBER
		{
			$$ = make_op_node(GT_EQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	|
	T_FIELD T_LT_EQ T_NUMBER
		{
			$$ = make_op_node(LT_EQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_int_node($3);
		}
	;

string_filter:
	T_FIELD '=' T_FIELD
		{
			$$ = make_op_node(EQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_string_node($3);
		}
	|
	T_FIELD T_NOT_EQ T_FIELD
		{
			$$ = make_op_node(NEQ);
			$$->left_child = make_field_node($1);
			$$->right_child = make_string_node($3);
		}
	;

%%


