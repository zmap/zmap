#define T_AND 257
#define T_OR 258
#define T_NUMBER 259
#define T_FIELD 260
#define T_NOT_EQ 261
#define T_GT_EQ 262
#define T_LT_EQ 263
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
	int int_literal;
	char *string_literal;
	struct node *expr; 
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
extern YYSTYPE yylval;
