TEST_APPS := orm_test_client

TARGETS := $(TEST_APPS:%=$(AppPattern))

all: $(TARGETS)

clean:
	@$(MakeClean)

orm_test_client: orm_test_client.py
	cp $< $@
