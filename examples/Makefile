#TODO LICENSE

TEST_EXAMPLES := matrix_multiplier/tests 
COVERAGE_MODEL_EXAMPLES := axi
ALL_EXAMPLES = $(TEST_EXAMPLES) $(COVERAGE_MODEL_EXAMPLES)

.PHONY: $(TEST_EXAMPLES)

.PHONY: all
all: $(ALL_EXAMPLES)

$(TEST_EXAMPLES):
	@cd $@ && $(MAKE) sim.coverage

$(COVERAGE_MODEL_EXAMPLES):
	@cd $@ && $(MAKE) coverage.sv

.PHONY: clean
clean:
	$(foreach TEST, $(ALL_EXAMPLES), $(MAKE) -C $(TEST) clean;)

regression:
	$(foreach TEST, $(ALL_EXAMPLES), $(MAKE) -C $(TEST) regression;)
