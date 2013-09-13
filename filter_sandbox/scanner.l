/* File:  scanner.l
 * ----------------
 * Lex input file to generate the scanner for the compiler.
 */

%{
#include <string.h>
#include "scanner.h"
#include "utility.h" // for PrintDebug()
#include "errors.h"
#include <math.h>
#include <iostream>
#include <cassert>

using std::string;
using std::cout;
using std::endl;

/* Global variable: yylval
 * -----------------------
 * This global variable is how we get attribute information about the token
 * just scanned to the client. The scanner sets the global variable
 * appropriately and since it's global the client can just read it.  In the
 * future, this variable will be declared for us in the y.tab.c file
 * produced by Yacc, but for now, we declare it manually.
 */
YYSTYPE yylval;  // manually declared for pp1, later Yacc provides

/* Global variable: yylloc
 * -----------------------
 * This global variable is how we get position information about the token
 * just scanned to the client. (Operates similarly to yylval above)
 */
struct yyltype yylloc; // manually dclared for pp1, later Yacc provides

/* Macro: YY_USER_ACTION 
 * ---------------------
 * This flex built-in macro can be defined to provide an action which is
 * always executed prior to any matched rule's action. Basically, it is
 * a way of having a piece of code common to all actions factored out to
 * this routine.  We already defined it for you and left the empty
 * function DoBeforeEachAction ready for your use as needed. It will
 * be called once for each pattern scanned from the file, before
 * executing its action.
 */
static void DoBeforeEachAction(); 
#define YY_USER_ACTION DoBeforeEachAction();

static void set_value(TokenType);

%}

ALPHA      [a-zA-Z]
ALPHANUM   [a-zA-Z0-9]
WORDCHAR   [a-zA-Z0-9_]
DIGIT      [0-9]
HEX        0(x|X)[0-9a-fA-F]+
WHITESPACE [ \t\n]

%%

 /* Keywords */
void       return T_Void;
int        return T_Int;
double     return T_Double;
bool       return T_Bool;
string     return T_String;
class      return T_Class;
interface  return T_Interface;
null       return T_Null;
this       return T_This;
extends    return T_Extends;
implements return T_Implements;
for        return T_For;
while      return T_While;
if         return T_If;
else       return T_Else;
return     return T_Return;
break      return T_Break;
New        return T_New;
NewArray   return T_NewArray;

 /* Type Constants */
true|false                                {set_value(T_BoolConstant); return T_BoolConstant;}
{HEX}|{DIGIT}+                            {set_value(T_IntConstant); return T_IntConstant;}
{DIGIT}+\.{DIGIT}*((E|e)(\+|-)?{DIGIT}+)? {set_value(T_DoubleConstant); return T_DoubleConstant;}
\"[^\"\n]*\"                              {set_value(T_StringConstant); return T_StringConstant;}
\"[^\"\n]*  	  	                      {ReportError::UntermString(&yylloc, yytext);}

 /* Whitespace */
{WHITESPACE} ;

 /* Identifier */
{ALPHA}{WORDCHAR}* {set_value(T_Identifier); return T_Identifier;}

 /* Operators */
"<="   return T_LessEqual;
>=     return T_GreaterEqual;
==     return T_Equal;
!=     return T_NotEqual;
&&     return T_And;
"||"   return T_Or;
\+     return '+';
-      return '-';
\*	   return '*';
\/	   return '/';
%	   return '%';
\<	   return '<';
\> 	   return '>';
=	   return '=';
!	   return '!';
;	   return ';';
,	   return ',';
\.	   return '.';
"["	   return '[';
"]"	   return ']';
"("	   return '(';
")"	   return ')';
"{"	   return '{';
"}"	   return '}'; 

.      ReportError::UnrecogChar(&yylloc, *yytext);

%%

static bool text_to_bool(char *yytext) {
  if (!strcmp(yytext, "true")) {
    return true;
  } else if (!strcmp(yytext, "false")) {
    return false;
  } else {
    Failure("Unrecognized value in function text_to_bool()");
  }

  // This will never be called
  exit(1);
}

static int text_to_int(char *yytext) {
  if (strlen(yytext) >= 2 && (yytext[1] == 'x' || yytext[1] == 'X')) {
    int num;
    int decimal = 0;
    for (int i = 2; i < yyleng; i++) {
      char c = isalpha(yytext[i]) ? toupper(yytext[i]) : yytext[i];
      switch(c) {
      case 'A': num = 10; break;
      case 'B': num = 11; break;
      case 'C': num = 12; break;
      case 'D': num = 13; break;
      case 'E': num = 14; break;
      case 'F': num = 15; break;
      default: num = yytext[i] - 48; break;
      }
      decimal += num * pow(16, yyleng - i - 1); // The exponent is the inverse of the char position
    }
    return decimal;
  }
  return atoi(yytext);
}

static double text_to_double(char *yytext) {
  int i = 0;
  double ret = 0;
  bool decimal = false;
  double divisor = 1;
  bool pose = true;
  bool exponent = false;
  std::string num;
  while(i < yyleng){
		num = num + yytext[i];
		if(yytext[i] == 'E' || yytext[i] == 'e'){
			exponent = true;
			ret = ret + atoi(num.c_str())/divisor;
			num.clear();
			if(yytext[i + 1] == '-'){
				pose = false;	
				i++;
			}
			else if(yytext[i + 1] == '+') i++;
		} 
		if(decimal) divisor *= 10;
		if(yytext[i] == '.'){
			ret = atoi(num.c_str());
			decimal = true;
			num.clear();
		}
		i++;
	}
			
  if(exponent) return ret * pow(10, atoi(num.c_str()));
  else return ret + atoi(num.c_str())/divisor;
}

static void set_identifier(char *identifier) {
  int num_chars = yyleng + 1; // The characters plus the null character
  if (yyleng > MaxIdentLen) {
    ReportError::LongIdentifier(&yylloc, yytext);
    num_chars = MaxIdentLen;
  }

  strncpy(identifier, yytext, num_chars);
  assert(identifier[MaxIdentLen + 1] == 0);
}

static void set_value(TokenType t) {
  switch(t) {
  case T_BoolConstant: yylval.boolConstant = text_to_bool(yytext); break;
  case T_IntConstant: yylval.integerConstant = text_to_int(yytext); break;
  case T_DoubleConstant: yylval.doubleConstant = text_to_double(yytext); break;
  case T_StringConstant: yylval.stringConstant = yytext; break;
  case T_Identifier: set_identifier(yylval.identifier); break;
  default: Failure("Unrecognized token %d in set_value()", (int) t);
  }
}

/* Function: InitScanner
 * ---------------------
 * This function will be called before any calls to yylex().  It is designed
 * to give you an opportunity to do anything that must be done to initialize
 * the scanner (set global variables, configure starting state, etc.). One
 * thing it already does for you is assign the value of the global variable
 * yy_flex_debug that controls whether flex prints debugging information
 * about each token and what rule was matched. If set to false, no information
 * is printed. Setting it to true will give you a running trail that might
 * be helpful when debugging your scanner. Please be sure the variable is
 * set to false when submitting your final version.
 */
void InitScanner()
{
    yy_flex_debug = false;
    PrintDebug("lex", "Initializing scanner");
}


/* Function: DoBeforeEachAction()
 * ------------------------------
 * This function is installed as the YY_USER_ACTION. This is a place
 * to group code common to all actions.
 */
static void DoBeforeEachAction()
{
  // TODO: This section looks hacky to me
  static int col_pos = 1;
  static int line_pos = 1;

  if (*yytext == '\n') {
    line_pos++;
    col_pos = 0;
  }

  yylloc.first_column = col_pos;
  yylloc.last_column = col_pos + yyleng - 1;
  yylloc.first_line = line_pos;

  col_pos += yyleng;
}
