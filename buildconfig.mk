#
# Build Configurations
#

CONFIG_DEBUG=debug
CONFIG_RELEASE=release
CONFIG_COVERAGE=coverage
CONFIG_DEFAULT=$(CONFIG_DEBUG)
# Select default if no value provided
ifeq ($(CONFIG),)
$(warning Configuration not specified - using default $(CONFIG_DEFAULT) configuration)
$(info )
CONFIG=$(CONFIG_DEFAULT)
endif

# This allows cleanall to work without having to specify a valid CONFIG value
$(info make command line $(MAKECMDGOALS))
ifneq "$(MAKECMDGOALS)" "cleanall"
ifneq ($(CONFIG),$(CONFIG_DEBUG))
ifneq ($(CONFIG),$(CONFIG_RELEASE))
ifneq ($(CONFIG),$(CONFIG_COVERAGE))
$(error Cannot support configuration '$(CONFIG)'.  Valid configurations: $(CONFIG_DEBUG), $(CONFIG_RELEASE), $(CONFIG_COVERAGE) (e.g. make CONFIG=$(CONFIG_DEFAULT)))
endif
endif
endif
endif

#
# Character Set
#

CHARSET_ANSI=ansi
CHARSET_UNICODE=unicode
CHARSET_DEFAULT=$(CHARSET_UNICODE)
# Select default if no value provided
ifeq ($(CHARSET),)
$(warning Character set not specified - using default of $(CHARSET_DEFAULT))
$(info )
CHARSET=$(CHARSET_DEFAULT)
endif

# Validate
ifneq ($(CHARSET),$(CHARSET_ANSI))
ifneq ($(CHARSET),$(CHARSET_UNICODE))
$(error Cannot support character set '$(CHARSET)'.  Valid configurations: $(CHARSET_ANSI), $(CHARSET_UNICODE) (e.g. make CHARSET=$(CHARSET_DEFAULT)))
endif
endif

#
# Optimization Level
#

OPTIMIZE_0=0
OPTIMIZE_1=1
OPTIMIZE_2=2
OPTIMIZE_3=3
OPTIMIZE_s=s
OPTIMIZE_fast=fast
ifeq ($(CONFIG),$(CONFIG_DEBUG))
OPTIMIZE_DEFAULT=$(OPTIMIZE_0)
endif
ifeq ($(CONFIG),$(CONFIG_RELEASE))
OPTIMIZE_DEFAULT=$(OPTIMIZE_s)
endif
ifeq ($(CONFIG),$(CONFIG_COVERAGE))
OPTIMIZE_DEFAULT=$(OPTIMIZE_0)
endif
# Select default if no value provided
ifeq ($(OPTIMIZE),)
$(warning Optimization not specified - using configuration-specific default of $(OPTIMIZE_DEFAULT) )
$(info )
OPTIMIZE=$(OPTIMIZE_DEFAULT)
endif

# Validate
ifneq ($(OPTIMIZE),$(OPTIMIZE_0))
ifneq ($(OPTIMIZE),$(OPTIMIZE_1))
ifneq ($(OPTIMIZE),$(OPTIMIZE_2))
ifneq ($(OPTIMIZE),$(OPTIMIZE_3))
ifneq ($(OPTIMIZE),$(OPTIMIZE_s))
ifneq ($(OPTIMIZE),$(OPTIMIZE_fast))
$(error Cannot support optimization level '$(OPTIMIZE)'.  Valid configurations: $(OPTIMIZE_0), $(OPTIMIZE_1), $(OPTIMIZE_2), $(OPTIMIZE_3), $(OPTIMIZE_s), $(OPTIMIZE_fast) (e.g. make OPTIMIZE=$(OPTIMIZE_DEFAULT)))
endif
endif
endif
endif
endif
endif


