#include "filter.h"
#include "state.h"
#include "lexer.h"
#include "y.tab.h"
#include "../lib/logger.h"

extern int yyparse();

node_t *zfilter;

void parse_filter_string(char *filter)
{
	YY_BUFFER_STATE buffer_state = yy_scan_string(filter);
	int status = yyparse();
	yy_delete_buffer(buffer_state);
	if (status) {
		// Error
		log_fatal("zmap", "Unable to parse filter");
	}
	zconf.filter.expression = zfilter;
	print_expression(zfilter);
	printf("%s\n", "");
	fflush(stdout);
	return;
}