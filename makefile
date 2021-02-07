PROC=pdb
CONFIGS=pdb.cfg

ifdef __NT__
  O1=old
  STDLIBS += ole32.lib
  STDLIBS += oleaut32.lib
else
  LIBS += $(L)network$(A)
endif

include ../plugin.mak

$(F)pdb$(O): CC_WNO-$(call gte,$(GCC_VERSION),6.1) += -Wno-null-dereference

# MAKEDEP dependency list ------------------
$(F)pdb$(O)     : $(I)allins.hpp $(I)auto.hpp $(I)bitrange.hpp              \
                  $(I)bytes.hpp $(I)config.hpp $(I)dbg.hpp                  \
                  $(I)demangle.hpp $(I)diskio.hpp $(I)err.h $(I)fpro.h      \
                  $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp       \
                  $(I)idp.hpp $(I)intel.hpp $(I)kernwin.hpp $(I)lines.hpp   \
                  $(I)llong.hpp $(I)loader.hpp $(I)md5.h $(I)nalt.hpp       \
                  $(I)name.hpp $(I)netnode.hpp $(I)network.hpp $(I)pro.h    \
                  $(I)range.hpp $(I)segment.hpp $(I)struct.hpp              \
                  $(I)typeinf.hpp $(I)ua.hpp $(I)workarounds.hpp            \
                  $(I)xref.hpp ../../dbg/win32/win32_rpc.h                  \
                  ../../ldr/pe/cor.h ../../ldr/pe/corhdr.h                  \
                  ../../ldr/pe/mycor.h ../../ldr/pe/pe.h common.cpp         \
                  cvconst.h dia2.h misc.cpp oldpdb.h pdb.cpp pdb.hpp        \
                  pdbaccess.hpp pdbremote.cpp pdbremote.hpp sip.cpp         \
                  sip.hpp tilbuild.cpp tilbuild.hpp varser.hpp
