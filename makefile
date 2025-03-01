PROC=pdb
CONFIGS=pdb.cfg

ifdef __NT__
  O1=old
endif

GOALS += pdbida
include ../plugin.mak

$(F)pdb$(O): CC_WNO-$(call gte,$(GCC_VERSION),6.1) += -Wno-null-dereference

