CURRENT_DIR=$(shell pwd)
LIB_PROC_MAPS_PARSER_DIR=$(CURRENT_DIR)/proc_maps_parser
LIB_PROC_MAPS_PARSER_INCLUDE_DIR=$(LIB_PROC_MAPS_PARSER_DIR)/include

all: injector payload

injector: injector.o $(LIB_PROC_MAPS_PARSER_DIR)/libproc_maps_parser.a
	gcc $? -L$(LIB_PROC_MAPS_PARSER_DIR) -lproc_maps_parser -o $@ 

payload: payload.c
	gcc -fpic -pie -nostdlib $? -o $@

injector.o: injector.c
	gcc -g -c $? -o $@ -I$(LIB_PROC_MAPS_PARSER_INCLUDE_DIR)

$(LIB_PROC_MAPS_PARSER_DIR)/libproc_maps_parser.a:
	$(MAKE) -C $(LIB_PROC_MAPS_PARSER_DIR)

clean:
	rm -rf *.o
	rm -rf injector
	rm -rf payload
	$(MAKE) -C $(LIB_PROC_MAPS_PARSER_DIR) clean
