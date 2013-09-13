/* File: parser.y
 * --------------
 * Yacc input file to generate the parser for the compiler.
 *
 * pp2: your job is to write a parser that will construct the parse tree
 *      and if no parse errors were found, print it.  The parser should 
 *      accept the language as described in specification, and as augmented 
 *      in the pp2 handout.
 */

%{

	/* Just like lex, the text within this first region delimited by %{ and %}
	 * is assumed to be C/C++ code and will be copied verbatim to the y.tab.c
	 * file ahead of the definitions of the yyparse() function. Add other header
	 * file inclusions or C++ variable declarations/prototypes that are needed
	 * by your code here.
	 */
#include "scanner.h" // for yylex
#include "parser.h"
#include "errors.h"
#include <iostream>
  using namespace std;
  void yyerror(const char *msg); // standard error-handling routine

%}

	/* The section before the first %% is the Definitions section of the yacc
	 * input file. Here is where you declare tokens and types, add precedence
	 * and associativity options, and so on.
	 */

	/* yylval 
	 * ------
	 * Here we define the type of the yylval global variable that is used by
	 * the scanner to store attibute information about the token just scanned
	 * and thus communicate that information to the parser. 
	 *
	 * pp2: You will need to add new fields to this union as you add different 
	 *      attributes to your non-terminal symbols.
	 */
	%union {
		int integerConstant;
		bool boolConstant;
		char *stringConstant;
		double doubleConstant;
		char identifier[MaxIdentLen+1]; // +1 for terminating null
		Decl *decl;
		VarDecl *varDecl;
		Case *caseNode;
		Default *defaultNode;
		List<Decl*> *declList;
		Stmt *stmt;
        List<Stmt*> *stmtList;
        List<VarDecl*> *varDeclList;
List<Case*> *caseList;
		Expr *expr;
		Type *type;
        List<Expr*> *exprList;
		List<NamedType*> *typeList;
	}

/* Tokens
 * ------
 * Here we tell yacc about all the token types that we are using.
 * Yacc will assign unique numbers to these and export the #define
 * in the generated y.tab.h header file.
 */
%token   T_Void T_Bool T_Int T_Double T_String T_Class 
%token   T_LessEqual T_GreaterEqual T_Equal T_NotEqual T_Dims
%token   T_And T_Or T_Null T_Extends T_This T_Interface T_Implements
%token   T_While T_For T_If T_Else T_Return T_Break
%token   T_New T_NewArray T_Print T_ReadInteger T_ReadLine

%token   <identifier> T_Identifier
%token   <stringConstant> T_StringConstant 
%token   <integerConstant> T_IntConstant
%token   <doubleConstant> T_DoubleConstant
%token   <boolConstant> T_BoolConstant

%token   T_Increm T_Decrem T_Switch T_Case T_Default

%nonassoc NON_ELSE 
%nonassoc T_Else
%nonassoc '='
%left T_Or 
%left T_And
%left T_Equal T_NotEqual
%nonassoc '<' T_LessEqual T_GreaterEqual '>' 
%left '+' '-'
%left '*' '/' '%'
%left NEG '!' INCRDECR
%left '[' '.'

/* Non-terminal types
 * ------------------
 * In order for yacc to assign/access the correct field of $$, $1, we
 * must to declare which field is appropriate for the non-terminal.
 * As an example, this first type declaration establishes that the DeclList
 * non-terminal uses the field named "declList" in the yylval union. This
 * means that when we are setting $$ for a reduction for DeclList ore reading
 * $n which corresponds to a DeclList nonterminal we are accessing the field
 * of the union named "declList" which is of type List<Decl*>.
 * pp2: You'll need to add many of these of your own.
 */
%type <declList>     DeclList    
%type <varDeclList>  VarDeclList 
%type <varDeclList>  Formals     
%type <decl>         Decl
%type <decl>         FnDecl
%type <varDecl>      VarDecl
%type <varDecl>      Variable
%type <stmt>         Stmt
%type <stmt>		 WhileStmt
%type <stmt>		 IfStmt
%type <stmt>		 ForStmt
%type <stmt>		 BreakStmt
%type <stmt>		 ReturnStmt
%type <stmt>		 PrintStmt
%type <stmt>		 StmtBlock
%type <stmtList>	 StmtList
%type <expr>		 Expr		   
%type <expr>		 EmptyExpr	 
%type <type>		 Type
%type <decl>         Field
%type <declList>         FieldList
%type <decl>         ClassDecl
%type <decl>         InterfaceDecl
%type <typeList>		 InterfaceList
%type <decl>         Prototype
%type <declList>     PrototypeList
%type <exprList>     ExprList
%type <exprList>     Actuals
%type <expr>         LValue
%type <expr>         Constant
%type <expr>         Call
%type <stmt>				 SwitchStmt
%type <caseList>     CaseList
%type <caseNode>     Case
%type <defaultNode>     Default

%%
/* Rules
 * -----
 * All productions and actions should be placed between the start and stop
 * %% markers which delimit the Rules section.

 */
Program	  :	   DeclList			   { 
	Program *program = new Program($1);
	// if no errors, advance to next phase
	if (ReportError::NumErrors() == 0) 
		program->Print(0);
 }
;

DeclList  :	   DeclList Decl		{ ($$=$1)->Append($2); }
|	 Decl				  { ($$ = new List<Decl*>)->Append($1); }
;

Decl	  :	   VarDecl		   { $$ = $1; }
|		 FnDecl			   {$$ = $1;}
|		 ClassDecl	           {$$ = $1;}
|		 InterfaceDecl		   {$$ = $1;}
;

VarDeclList	 :	  VarDeclList VarDecl		 { ($$=$1)->Append($2); }
|				VarDecl { ($$ = new List<VarDecl*>)->Append($1); }
;

VarDecl : Variable ';'							{$$ = $1;};	

Variable : Type T_Identifier					{$$ = new VarDecl(new Identifier(@2, $2), $1); };

ClassDecl : T_Class T_Identifier '{' FieldList '}' {$$ = new ClassDecl(new Identifier(@2, $2), 0, new List<NamedType*>, $4);}
|				T_Class T_Identifier T_Extends T_Identifier '{' FieldList '}' {$$ = new ClassDecl(new Identifier(@2, $2), new NamedType(new Identifier(@4, $4)), new List<NamedType*>, $6);}
				|				T_Class T_Identifier T_Extends T_Identifier T_Implements InterfaceList '{' FieldList '}' {$$ = new ClassDecl(new Identifier(@2, $2), new NamedType(new Identifier(@4, $4)), $6, $8);}
				|				T_Class T_Identifier T_Implements InterfaceList '{' FieldList '}' {$$ = new ClassDecl(new Identifier(@2, $2), 0, $4, $6);}
;

InterfaceList: T_Identifier ',' InterfaceList {($$=$3)->Append(new NamedType(new Identifier(@1, $1)));}
|				T_Identifier {($$=new List<NamedType*>)->Append(new NamedType(new Identifier(@1, $1)));}

FieldList : FieldList Field {($$ = $1)->Append($2);}
				|				/* empty */ {$$ = new List<Decl*>;}
;

 Type:	T_Int													{$$ = Type::intType; }
   | T_Double															{$$ = Type::doubleType; }
   |T_Bool																{$$ = Type::boolType; }
   |T_String															{$$ = Type::stringType; }
   |T_Identifier							{$$ = new NamedType(new Identifier(@1, $1)); }
|Type T_Dims								{$$ = new ArrayType(@1, $1); }
;

FnDecl	:	Type T_Identifier '(' Formals ')' StmtBlock		{$$ = new FnDecl(new Identifier(@2, $2), $1, $4); ((FnDecl *)$$)->SetFunctionBody($6); }
| T_Void T_Identifier '(' Formals ')' StmtBlock				{$$ = new FnDecl(new Identifier(@2, $2), Type::voidType, $4); ((FnDecl *)$$)->SetFunctionBody($6); }
;

Formals : Variable						  {($$ = new List<VarDecl*>)->Append($1);}
|	Formals ',' Variable					  {($$ = $1)->Append($3);}
|								  {$$ = new List<VarDecl*>;}
;

Field : VarDecl							{$$ = $1;}
|	FnDecl							{$$ = $1;}
;

InterfaceDecl	: T_Interface T_Identifier '{' PrototypeList '}'			{$$ = new InterfaceDecl(new Identifier(@2, $2), $4);};

PrototypeList : PrototypeList Prototype {($$=$1)->Append($2);}
| {$$ = new List<Decl*>;}
;
Prototype	:		Type T_Identifier	'(' Formals ')' ';'			{$$ = new FnDecl(new Identifier(@2, $2), $1, $4);}
   |	T_Void T_Identifier '(' Formals ')' ';'						{$$ = new FnDecl(new Identifier(@2, $2), Type::voidType, $4);}
;

StmtBlock	: '{'	VarDeclList StmtList '}'					{ $$ = new StmtBlock($2, $3);}
				|				'{'	VarDeclList '}'				{ $$ = new StmtBlock($2, new List<Stmt*>);}
				|				'{'	StmtList '}'					{ $$ = new StmtBlock(new List<VarDecl*>, $2);}
|				'{' '}'                   { $$ = new StmtBlock(new List<VarDecl*>, new List<Stmt*>);}
;

StmtList  :	   StmtList Stmt		{ ($$=$1)->Append($2);}
|				Stmt { ($$ = new List<Stmt*>)->Append($1); }
;

Stmt		:	EmptyExpr ';'													{$$ = $1; }
   |		IfStmt																	{$$ = $1; }  									
	 |		WhileStmt																{$$ = $1; }
   |		ForStmt																	{$$ = $1; }
   |		BreakStmt					                      {$$ = $1; }										
   |		ReturnStmt					                    {$$ = $1; }					
   |		PrintStmt											          {$$ = $1; }
   |	StmtBlock											            {$$ = $1; }
				|				SwitchStmt                      {$$ = $1; }
;

IfStmt	:	T_If '(' Expr ')' Stmt	 %prec NON_ELSE {$$ = new IfStmt($3, $5, 0); }
	 | T_If '(' Expr ')' Stmt T_Else Stmt						{ $$ = new IfStmt($3, $5, $7); }
	 ;
SwitchStmt : T_Switch '(' Expr ')' '{' CaseList Default '}'    { $$ = new SwitchStmt($3, $6, $7);}
				|				T_Switch '(' Expr ')' '{' CaseList '}'    { $$ = new SwitchStmt($3, $6, 0);};

CaseList : CaseList Case {($$ = $1)->Append($2);}
| Case                           {($$ = new List<Case*>)->Append($1);}
;

Case : T_Case T_IntConstant ':' StmtList {$$ = new Case(new IntConstant(@2, $2), $4);}
| T_Case T_IntConstant ':'                     {$$ = new Case(new IntConstant(@2, $2), new List<Stmt*>);};

Default : T_Default ':' StmtList {$$ = new Default($3);}
| T_Default ':'                      {$$ = new Default(new List<Stmt*>);};

WhileStmt	:	T_While '(' Expr ')' Stmt						{$$ = new WhileStmt($3, $5); }
;
ForStmt		:	T_For '(' EmptyExpr ';' Expr ';' EmptyExpr ')' Stmt		{$$ = new ForStmt($3, $5, $7, $9); }
;

ReturnStmt	:	T_Return EmptyExpr ';'					{ $$ = new ReturnStmt(@1, $2); };

BreakStmt	:	T_Break ';'							{$$ = new BreakStmt(@1); };

PrintStmt	:	T_Print '(' ExprList ')' ';'					{$$ = new PrintStmt($3);};

ExprList	:	Expr							{($$ = new List<Expr*>)->Append($1);}
	 |	ExprList ',' Expr							{($$ = $1)->Append($3);}
;

   EmptyExpr : Expr {$$ = $1; }
       | {$$ = new EmptyExpr; }
     ;

Expr :	LValue '=' Expr		{$$ = new AssignExpr($1, new Operator(@2, "=") , $3); };
|	Constant		{$$ = $1;}
|	LValue			{$$ = $1; }
| T_This			{$$ = new This(@1);}
| Call				{$$ = $1;}
|'(' Expr ')' 		        {$$ = $2;}	
| Expr '+' Expr		        {$$ = new ArithmeticExpr($1, new Operator(@2, "+"), $3);}
| Expr '-' Expr			{$$ = new ArithmeticExpr($1, new Operator(@2, "-"), $3);}
| Expr '*' Expr			{$$ = new ArithmeticExpr($1, new Operator(@2, "*"), $3);}
| Expr '/' Expr			{$$ = new ArithmeticExpr($1, new Operator(@2, "/"), $3);}
| Expr '%' Expr			{$$ = new ArithmeticExpr($1, new Operator(@2, "%"), $3);}
| '-' Expr %prec NEG   {$$ = new ArithmeticExpr(new Operator(@2, "-"), $2);}
| Expr '<' Expr 		{$$ = new RelationalExpr($1, new Operator(@2, "<"), $3);}
| Expr T_LessEqual Expr		{$$ = new RelationalExpr($1, new Operator(@2, "<="), $3);}
| Expr '>' Expr 		{$$ = new RelationalExpr($1, new Operator(@2, ">"), $3);}
| Expr T_GreaterEqual Expr	{$$ = new RelationalExpr($1, new Operator(@2, ">="), $3);}
| Expr T_Equal Expr 		{$$ = new EqualityExpr($1, new Operator(@2, "=="), $3);}
| Expr T_NotEqual Expr 		{$$ = new EqualityExpr($1, new Operator(@2, "!="), $3);}
| Expr T_And Expr 		{$$ = new LogicalExpr($1, new Operator(@2, "&&"), $3);}
| Expr T_Or Expr 		{$$ = new LogicalExpr($1, new Operator(@2, "||"), $3);}
| '!' Expr 		        {$$ = new LogicalExpr(new Operator(@1, "!"), $2);}     
| T_ReadInteger '(' ')'         {$$ = new ReadIntegerExpr(@1);}
| T_ReadLine '(' ')'            {$$ = new ReadLineExpr(@1);}
| T_New '(' T_Identifier ')'    {$$ = new NewExpr(@1, new NamedType(new Identifier(@3, $3)) );}
| T_NewArray '('Expr ',' Type')' {$$ = new NewArrayExpr(@1, $3, $5);}
| LValue T_Increm 	%prec INCRDECR		{$$ = new PostfixExpr($1, new Operator(@2, "++"));}
| LValue T_Decrem 	%prec INCRDECR		{$$ = new PostfixExpr($1, new Operator(@2, "--"));}
;

LValue	:	T_Identifier	   		 {$$ = new FieldAccess(0, new Identifier(@1, $1)); }
| Expr '.' T_Identifier	   		     {$$ = new FieldAccess($1, new Identifier(@3, $3));}
| Expr '[' Expr ']'					 {$$ = new ArrayAccess(@1, $1, $3);}
;

Call	: T_Identifier	'(' Actuals ')'					{$$ = new Call(@1, 0, new Identifier(@1, $1), $3);}
| Expr '.' T_Identifier '(' Actuals ')'					{$$ = new Call(@1, $1, new Identifier(@3, $3), $5);}
;

Actuals:	ExprList 							{$$ = $1;}
|	                                            {$$ = new List<Expr*>;}
;

Constant:	T_IntConstant 			  {$$ = new IntConstant(@1, $1);}
| T_DoubleConstant					  {$$ = new DoubleConstant(@1, $1);}
| T_BoolConstant					  {$$ = new BoolConstant(@1, $1);}
| T_StringConstant					  {$$ = new StringConstant(@1, $1);}
| T_Null					   		  {$$ = new NullConstant(@1); }
;
%%

/* The closing %% above marks the end of the Rules section and the beginning
 * of the User Subroutines section. All text from here to the end of the
 * file is copied verbatim to the end of the generated y.tab.c file.
 * This section is where you put definitions of helper functions.
 */

/* Function: InitParser
 * --------------------
 * This function will be called before any calls to yyparse().  It is designed
 * to give you an opportunity to do anything that must be done to initialize
 * the parser (set global variables, configure starting state, etc.). One
 * thing it already does for you is assign the value of the global variable
 * yydebug that controls whether yacc prints debugging information about
 * parser actions (shift/reduce) and contents of state stack during parser.
 * If set to false, no information is printed. Setting it to true will give
 * you a running trail that might be helpful when debugging your parser.
 * Please be sure the variable is set to false when submitting your final
 * version.
 */
void InitParser()
{
	PrintDebug("parser", "Initializing parser");
	yydebug = false;
}
