%{
#include <string.h>
#include "y.tab.h"
%}

%%
[0-9]+               yylval.int_literal = atoi(yytext); return T_NUMBER;
\n                   /* Ignore end of line */
[ \t]+               /* Ignore whitespace */
!=                   return T_NOT_EQ;
>=                   return T_GT_EQ;
"<="                 return T_LT_EQ;
&&                   return T_AND;
"||"                 return T_OR;
=                    return '=';
">"                  return '>';
"<"                  return '<';
"("                  return '(';
")"                  return ')';
[a-zA-Z][a-zA-Z0-9]+ yylval.string_literal = strdup(yytext); return T_FIELD;

%%