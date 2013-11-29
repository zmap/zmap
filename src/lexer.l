%{
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wmissing-noreturn"

#include <string.h>
#include "parser.h"

%}

%option noinput
%option nounput
%%
[0-9]+               yylval.int_literal = (uint64_t) atoll(yytext); return T_NUMBER;
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